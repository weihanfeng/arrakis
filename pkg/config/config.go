package config

import (
	"fmt"

	"github.com/spf13/viper"
)

const (
	CodeServerPort  = "4030"
	serverConfigKey = "hostservices.restserver"
	clientConfigKey = "hostservices.client"
)

type ServerConfig struct {
	Host         string `mapstructure:"host"`
	Port         string `mapstructure:"port"`
	StateDir     string `mapstructure:"state_dir"`
	BridgeName   string `mapstructure:"bridge_name"`
	BridgeIP     string `mapstructure:"bridge_ip"`
	BridgeSubnet string `mapstructure:"bridge_subnet"`
	ChvBinPath   string `mapstructure:"chv_bin"`
	KernelPath   string `mapstructure:"kernel"`
	RootfsPath   string `mapstructure:"rootfs"`
}

func (c ServerConfig) String() string {
	return fmt.Sprintf(`{
Host: %s
Port: %s
StateDir: %s
BridgeName: %s
BridgeIP: %s
BridgeSubnet: %s
KernelPath: %s
ChvBinPath: %s
}`, c.Host, c.Port, c.StateDir, c.BridgeName, c.BridgeIP, c.BridgeSubnet, c.KernelPath, c.ChvBinPath)
}

type ClientConfig struct {
	ServerHost string `mapstructure:"server_host"`
	ServerPort string `mapstructure:"server_port"`
}

func (c ClientConfig) String() string {
	return fmt.Sprintf(`{
ServerHost: %s
ServerPort: %s
}`, c.ServerHost, c.ServerPort)
}

func GetServerConfig(configFile string) (*ServerConfig, error) {
	viper.SetConfigFile(configFile)
	err := viper.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %v", err)
	}

	restServerConfig := viper.Sub(serverConfigKey)
	if restServerConfig == nil {
		return nil, fmt.Errorf("restserver configuration not found")
	}

	var result ServerConfig
	if err := restServerConfig.Unmarshal(&result); err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %v", err)
	}
	return &result, nil
}

func GetClientConfig(configFile string) (*ClientConfig, error) {
	viper.SetConfigFile(configFile)
	err := viper.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %v", err)
	}

	clientConfig := viper.Sub(clientConfigKey)
	if clientConfig == nil {
		return nil, fmt.Errorf("client configuration not found")
	}

	var result ClientConfig
	if err := clientConfig.Unmarshal(&result); err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %v", err)
	}
	return &result, nil
}
