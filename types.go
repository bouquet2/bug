package main

import (
    "io"
    "net/http"
    "net/url"
    "sync"
)

type backendURL struct {
	URL     *url.URL
	Options BackendRefOptions
}

type BackendRef struct {
	IP       string            `mapstructure:"ip"`
	Port     int               `mapstructure:"port"`
	Protocol string            `mapstructure:"protocol"`
	TLS      TLS               `mapstructure:"tls"`
	Options  BackendRefOptions `mapstructure:"options"`
}

type BackendRefOptions struct {
	InsecureSkipVerify bool `mapstructure:"insecureSkipVerify"`
}

type Rule struct {
	BackendRefs        []BackendRef `mapstructure:"backendRefs"`
	InsecureSkipVerify bool         `mapstructure:"insecureSkipVerify"`
}

type Limit struct {
	Requests int `mapstructure:"requests"`
	Every    int `mapstructure:"every"`
}

type Path struct {
	Path     string `mapstructure:"path"`
	PathType string `mapstructure:"type"`
	Limit    Limit  `mapstructure:"limit"`
}

type Route struct {
	Name      string   `mapstructure:"name"`
	Lb        string   `mapstructure:"lb"`
	Hostnames []string `mapstructure:"hostnames"`
	Paths     []Path   `mapstructure:"paths"`
	Rules     []Rule   `mapstructure:"rules"`
}

type TLS struct {
	Cert             string `mapstructure:"cert"`
	Key              string `mapstructure:"key"`
}

type Bug struct {
	Debug    bool   `mapstructure:"debug"`
	Ip       string `mapstructure:"ip"`
	Port     int    `mapstructure:"port"`
	Protocol string `mapstructure:"protocol"`
	Lb       string `mapstructure:"lb"`
	Tls      TLS    `mapstructure:"tls"`
	Limit    Limit  `mapstructure:"limit"`
}

// Listen defines the bind address for a TCP/UDP stream proxy
type Listen struct {
    Ip   string `mapstructure:"ip"`
    Port int    `mapstructure:"port"`
}

// Stream defines a raw TCP/UDP forwarding stream with optional load balancing
// The structure intentionally mirrors HTTP routes where possible to preserve
// configuration consistency across protocols.
type Stream struct {
    Name     string `mapstructure:"name"`
    Protocol string `mapstructure:"protocol"` // acceptable values: tcp, udp
    Lb       string `mapstructure:"lb"`
    Listen   Listen `mapstructure:"listen"`
    Rules    []Rule `mapstructure:"rules"`
}

type Config struct {
	Version      int              `mapstructure:"version"`
	Bug          Bug              `mapstructure:"bug"`
	Routes       []Route          `mapstructure:"routes"`
    Streams      []Stream         `mapstructure:"streams"`
}

type App struct {
	handler http.Handler
	config  *Config
	mu      sync.RWMutex
    // streamClosers hold running TCP/UDP stream servers which must be closed on reload
    streamClosers []io.Closer
}
