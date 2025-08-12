package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	stdlog "log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// errorWriter implements io.Writer and logs messages at error level using zerolog
type errorWriter struct{}

func (w *errorWriter) Write(p []byte) (n int, err error) {
	log.Error().Msg(string(p))
	return len(p), nil
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	a.handler.ServeHTTP(w, r)
}

func (a *App) reload() {
	log.Debug().Any("config", a.config).Msg("reloading configuration")
    handler := SetupRoutes(a.config)
    // Stop previous streams if any
    if len(a.streamClosers) > 0 {
        for _, c := range a.streamClosers {
            if c != nil {
                _ = c.Close()
            }
        }
        a.streamClosers = nil
    }
    // Start new streams from config
    a.streamClosers = startStreams(a.config)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.handler = handler
}

func main() {
	fmt.Println(`
___.__.                 
\_ |__  __ __  ____  
 | __ \|  |  \/ ___\ 
 | \_\ \  |  / /_/  >
 |___  /____/\___  / 
     \/     /_____/`)
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	log.Info().Str("version", version).Msg("bug - simple load balancer/reverse proxy")

	config, err := LoadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("fatal error config file")
	}

	app := &App{
		config: config,
	}
	app.reload()

	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Info().Str("file", e.Name).Msg("Config file changed")
		if err := viper.Unmarshal(app.config); err != nil {
			log.Error().Err(err).Msg("error unmarshalling config")
		}
		app.reload()
		log.Debug().Any("config", app.config).Msg("Configuration reloaded")
	})
	viper.WatchConfig()

	// Enable debug logging if specified in config
	if viper.GetBool("bug.debug") {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	log.Debug().Any("config", config).Msg("Configuration loaded")

	// Create a custom writer that logs HTTP server errors at error level
	errorLogWriter := &errorWriter{}

	server := &http.Server{
		Addr:         config.Bug.Ip + ":" + strconv.Itoa(config.Bug.Port),
		Handler:      app,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		ErrorLog:     stdlog.New(errorLogWriter, "", 0),
	}

	log.Info().Msg("Starting on " + config.Bug.Protocol + "://" + config.Bug.Ip + ":" + strconv.Itoa(config.Bug.Port))
	if config.Bug.Protocol == "https" {
		certFile := config.Bug.Tls.Cert
		keyFile := config.Bug.Tls.Key

		if certFile == "" || keyFile == "" {
			log.Warn().Msg("TLS cert or key file not specified, generating self-signed certificate")
			certPEM, keyPEM, err := generateSelfSignedCert()
			if err != nil {
				log.Fatal().Err(err).Msg("failed to generate self-signed certificate")
			}

			// Create TLS config with in-memory certificate
			cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
			if err != nil {
				log.Fatal().Err(err).Msg("failed to create X509 key pair")
			}

			server.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
			}

			if err := server.ListenAndServeTLS("", ""); err != nil {
				log.Fatal().Err(err).Msg("server failed to start")
			}
		} else {
			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
				log.Fatal().Err(err).Msg("server failed to start")
			}
		}
	} else {
		if err := server.ListenAndServe(); err != nil {
			log.Fatal().Err(err).Msg("server failed to start")
		}
	}
}

func generateSelfSignedCert() (string, string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"bug"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add localhost to the SANs
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	template.DNSNames = append(template.DNSNames, "localhost")

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	// Create certificate PEM in memory
	var certPEM strings.Builder
	if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return "", "", err
	}

	// Create private key PEM in memory
	var keyPEM strings.Builder
	if err := pem.Encode(&keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return "", "", err
	}

	return certPEM.String(), keyPEM.String(), nil
}
