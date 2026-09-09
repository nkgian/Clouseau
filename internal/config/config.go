package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Task struct {
	Name    string                 `yaml:"name"`
	Params  map[string]interface{} `yaml:"params"`
}

type Config struct {
	Tasks []Task `yaml:"tasks"`
}

// LoadConfig reads the YAML file from disk and parses it into our structs
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
