package main

import (
	"flag"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"

	"github.com/ilyaluk/bastion/internal/bastion"
)

func main() {
	configFilename := flag.String("config", "config.yaml", "Configuration file")
	flag.Parse()

	if _, err := os.Stat(*configFilename); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Configuration file not found")
		flag.PrintDefaults()
		os.Exit(1)
	}

	config, err := bastion.ReadConfig(*configFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		flag.PrintDefaults()
		os.Exit(1)
	}

	logconfig := zap.NewDevelopmentConfig()
	logconfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger, err := logconfig.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	if config.StandaloneMode {
		if err := bastion.RunStandalone(config, sugaredLogger); err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			os.Exit(1)
		}
	} else {
		if err := bastion.Run(config, sugaredLogger); err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			os.Exit(1)
		}
	}
}
