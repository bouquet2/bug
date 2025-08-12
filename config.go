package main

import (
	"github.com/spf13/viper"
)

func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	viper.SetDefault("bug.ip", "0.0.0.0")
	viper.SetDefault("bug.port", 8080)
	viper.SetDefault("bug.protocol", "http")
	viper.SetDefault("bug.debug", false)
	viper.SetDefault("bug.lb", "roundrobin")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
