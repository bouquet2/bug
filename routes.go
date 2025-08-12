package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sirupsen/logrus"
	"github.com/vulcand/oxy/ratelimit"
	"github.com/vulcand/oxy/utils"
	"github.com/vulcand/oxy/v2/forward"
	"github.com/vulcand/oxy/v2/roundrobin"
)

const (
	version = "1.0.0"
)

var supportedLbTypes = []string{"roundrobin", "none"}
var supportedHTTPProtocols = []string{"http", "https"}

// Custom error handler for rate limiting that uses zerolog
type rateLimitErrorHandler struct{}

func (h *rateLimitErrorHandler) ServeHTTP(w http.ResponseWriter, req *http.Request, err error) {
	log.Warn().
		Err(err).
		Str("method", req.Method).
		Str("url", req.URL.String()).
		Str("host", req.Host).
		Str("remote_addr", req.RemoteAddr).
		Msg("Rate limit exceeded")

	http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
}

func NewProxy(backendURLs []*url.URL, hostnames []string, lbType string, insecureSkipVerify bool, limit *Limit) http.Handler {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
	}

	fwd := forward.New(false)
	fwd.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Add error handler to log backend failures
	fwd.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		log.Error().
			Err(err).
			Str("method", req.Method).
			Str("url", req.URL.String()).
			Str("host", req.Host).
			Msg("Backend request failed")
		http.Error(w, "Backend service unavailable", http.StatusBadGateway)
	}

	var handler http.Handler

	var lb *roundrobin.RoundRobin

	if len(backendURLs) > 1 && lbType == "roundrobin" {
		log.Debug().Str("load_balancer", lbType).Int("backendURLs", len(backendURLs)).Strs("hostnames", hostnames).Msg("Enabled roundrobin load balancing")
		var err error
		lb, err = roundrobin.New(fwd)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create round robin load balancer")
		}

		for _, backendURL := range backendURLs {
			if err := lb.UpsertServer(backendURL); err != nil {
				log.Error().Err(err).Str("backend", backendURL.String()).Msg("Failed to add backend to load balancer")
			}
		}
		handler = lb
	} else {
		handler = fwd
	}

	// Apply rate limiting if configured
	if limit != nil && limit.Requests > 0 && limit.Every > 0 {
		// Create a SourceExtractor that extracts client IP
		extractor, err := utils.NewExtractor("client.ip")
		if err != nil {
			log.Error().Err(err).Msg("Failed to create source extractor")
		} else {
			// Create rate set with the configured limits
			rates := ratelimit.NewRateSet()
			err := rates.Add(time.Duration(limit.Every)*time.Second, int64(limit.Requests), int64(limit.Requests))
			if err != nil {
				log.Error().Err(err).Msg("Failed to add rate to rate set")
			} else {
				// Create a logrus logger that discards output to suppress internal logs
				discardLogger := logrus.New()
				discardLogger.SetOutput(io.Discard)

				rateLimiter, err := ratelimit.New(handler, extractor, rates,
					ratelimit.ErrorHandler(&rateLimitErrorHandler{}),
					ratelimit.Logger(discardLogger))
				if err != nil {
					log.Error().Err(err).Msg("Failed to create rate limiter")
				} else {
					log.Debug().Int("requests", limit.Requests).Int("every", limit.Every).Msg("Rate limiting enabled")
					handler = rateLimiter
				}
			}
		}
	}

	// Create a handler that logs requests and forwards them
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Add custom headers
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Powered-By", "bug proxy "+version)

		log.Debug().
			Str("method", req.Method).
			Str("url", req.URL.String()).
			Str("host", req.Host).
			Msg("Proxying request")

		if lb != nil {
			log.Debug().Msg("Using load balancer")
		} else {
			log.Debug().Str("backend", backendURLs[0].String()).Msg("Using single backend")
			req.URL.Scheme = backendURLs[0].Scheme
			req.URL.Host = backendURLs[0].Host
		}

		handler.ServeHTTP(w, req)

		// Remove the X-Powered-By header from response if present
		w.Header().Del("X-Powered-By")
	})
}

func SetupRoutes(config *Config) http.Handler {
	if len(config.Routes) == 0 {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "No routes configured", http.StatusInternalServerError)
		})
	}

	type routeKey struct {
		hostname string
		path     Path
	}

	routeMap := make(map[routeKey]http.Handler)
	log.Info().Msgf("Setting up %d routes", len(config.Routes))

	for _, route := range config.Routes {
		if len(route.Rules) == 0 || len(route.Rules[0].BackendRefs) == 0 {
			log.Warn().Msgf("Route %s has no rules or backend references", route.Name)
			continue
		}

		for _, rule := range route.Rules {
			var backendURLs []*url.URL

            for _, backend := range rule.BackendRefs {
                // Determine protocol - default to http if not specified
                protocol := backend.Protocol
                if protocol == "" {
                    protocol = "http"
                }

                // Enforce that HTTP routes only support http/https
                if !slices.Contains(supportedHTTPProtocols, strings.ToLower(protocol)) {
                    log.Error().
                        Str("route", route.Name).
                        Str("protocol", protocol).
                        Msg("Invalid protocol for HTTP route backend (only http/https allowed). Use streams for tcp/udp.")
                    continue
                }

                backendURL, err := url.Parse(fmt.Sprintf("%s://%s:%d", protocol, backend.IP, backend.Port))
                if err != nil {
                    log.Error().Err(err).Msgf("Invalid backend URL for route %s", route.Name)
                    continue
                }

                log.Debug().
                    Str("route", route.Name).
                    Str("backend_url", backendURL.String()).
                    Str("protocol", protocol).
                    Msg("Added backend to route")

                backendURLs = append(backendURLs, backendURL)
            }

            if len(backendURLs) == 0 {
                log.Warn().Str("route", route.Name).Msg("No valid HTTP backends for rule; skipping rule")
                continue
            }

			var lbType string

			if route.Lb != "" {
				lbType = route.Lb
			} else {
				lbType = config.Bug.Lb
			}

			if !slices.Contains(supportedLbTypes, lbType) {
				log.Error().Msgf("Invalid load balancing policy for route %s", route.Name)
				continue
			}

			paths := route.Paths
			if len(paths) == 0 {
				paths = []Path{Path{Path: "/", PathType: "Prefix"}}
			}

			for _, hostname := range route.Hostnames {
				for _, path := range paths {
					var rateLimit *Limit
					if path.Limit.Requests > 0 && path.Limit.Every > 0 {
						rateLimit = &path.Limit
						log.Debug().
							Str("route", route.Name).
							Str("path", path.Path).
							Int("requests", path.Limit.Requests).
							Int("every", path.Limit.Every).
							Msg("Using path-specific rate limit")
					} else if config.Bug.Limit.Requests > 0 && config.Bug.Limit.Every > 0 {
						rateLimit = &config.Bug.Limit
						log.Debug().
							Str("route", route.Name).
							Str("path", path.Path).
							Int("requests", config.Bug.Limit.Requests).
							Int("every", config.Bug.Limit.Every).
							Msg("Using global Bug rate limit")
					} else {
						log.Debug().Str("route", route.Name).Str("path", path.Path).Msg("Using no rate limit")
						rateLimit = nil
					}

					pathProxy := NewProxy(backendURLs, route.Hostnames, lbType, rule.InsecureSkipVerify, rateLimit)

					key := routeKey{hostname: hostname, path: path}
					routeMap[key] = pathProxy
					log.Debug().Str("hostname", hostname).Str("path", path.Path).Str("pathType", path.PathType).Str("route", route.Name).Msg("Mapped hostname and path to route")
				}
			}
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host

		if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
			host = host[:colonIndex]
		}

		path := r.URL.Path

		var matchedHandler http.Handler
		var bestMatch string

		for key, handler := range routeMap {
			if key.hostname == host {
				var matches bool
				var matchLength int

				switch strings.ToLower(key.path.PathType) {
				case "prefix":
					if strings.HasPrefix(path, key.path.Path) {
						matches = true
						matchLength = len(key.path.Path)
					}
				case "exact":
					if path == key.path.Path {
						matches = true
						matchLength = len(key.path.Path)
					}
				default:
					if strings.HasPrefix(path, key.path.Path) {
						matches = true
						matchLength = len(key.path.Path)
					}
				}

				if matches && matchLength > len(bestMatch) {
					bestMatch = key.path.Path
					matchedHandler = handler
				}
			}
		}

		if matchedHandler != nil {
			log.Debug().Str("host", host).Str("path", path).Str("matched_path", bestMatch).Msg("Routing request to matched route")
			matchedHandler.ServeHTTP(w, r)
		} else {
			log.Warn().Str("host", host).Str("path", path).Msg("No route found for host and path")
			http.Error(w, "404 Not Found", http.StatusNotFound)
		}
	})
}
