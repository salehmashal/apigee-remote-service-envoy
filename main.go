// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apigee/apigee-remote-service-envoy/v2/server"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

const (
	prometheusPath = "/metrics"
)

// populated via ldflags
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

var (
	logLevel            string
	logJSON             bool
	configFile          string
	policySecretPath    string
	analyticsSecretPath string
)

func main() {

	rootCmd := &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {

			logLevel := log.ParseLevel(logLevel)

			// use zap logger instead of default
			var zapConfig zap.Config
			if logJSON {
				zapConfig = zap.NewProductionConfig()
			} else { // console
				zapConfig = zap.NewDevelopmentConfig()
				zapConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
			}
			var zapLevel zapcore.Level
			switch logLevel {
			case log.Debug:
				zapLevel = zap.DebugLevel
			case log.Info:
				zapLevel = zap.InfoLevel
			case log.Warn:
				zapLevel = zap.WarnLevel
			case log.Error:
				zapLevel = zap.ErrorLevel
			}
			zapConfig.Level = zap.NewAtomicLevelAt(zapLevel)

			logger, _ := zapConfig.Build(zap.AddCallerSkip(2))
			defer func() {
				_ = logger.Sync()
			}()
			sugaredLogger := logger.Sugar()
			log.Log = &log.LevelWrapper{
				Logger:   sugaredLogger,
				LogLevel: logLevel,
			}

			fmt.Printf("apigee-remote-service-envoy version %s %s [%s]\n", version, date, commit)

			config := server.DefaultConfig()
			if err := config.Load(configFile, policySecretPath, analyticsSecretPath, true); err != nil {
				log.Errorf("Unable to load config: %s:\n%v", configFile, err)
				os.Exit(1)
			}

			b, _ := json.Marshal(config)
			log.Debugf("Config: \n%v", string(b))

			serve(config)
			select {} // infinite loop
		},
	}
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "Logging level")
	rootCmd.Flags().BoolVarP(&logJSON, "json-log", "j", false, "Log as JSON")
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "Config file")
	rootCmd.Flags().StringVarP(&policySecretPath, "policy-secret", "p", "/policy-secret", "Policy secret mount point")
	rootCmd.Flags().StringVarP(&analyticsSecretPath, "analytics-secret", "a", server.DefaultAnalyticsSecretPath, "Analytics secret mount point")

	rootCmd.SetArgs(os.Args[1:])
	if err := rootCmd.Execute(); err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
}

func serve(config *server.Config) {

	// gRPC server
	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionAge: config.Global.KeepAliveMaxConnectionAge,
		}),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
	}

	if config.Global.TLS.CertFile != "" {
		creds, err := credentials.NewServerTLSFromFile(config.Global.TLS.CertFile, config.Global.TLS.KeyFile)
		if err != nil {
			panic(err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	grpcServer := grpc.NewServer(opts...)
	grpc_prometheus.Register(grpcServer)

	// Apigee Remote Service
	rsHandler, err := server.NewHandler(config)
	if err != nil {
		log.Errorf("gRPC NewHandler: %v", err)
		panic(err)
	}
	as := &server.AuthorizationServer{}
	as.Register(grpcServer, rsHandler)
	ls := &server.AccessLogServer{}
	ls.Register(grpcServer, rsHandler, config.Global.KeepAliveMaxConnectionAge)
	eps := &server.ExtProcServer{}
	eps.Register(grpcServer, rsHandler)
	// grpc health
	grpcHealth := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, grpcHealth)

	kubeHealth := server.NewKubeHealth(rsHandler, grpcHealth)

	reflection.Register(grpcServer)

	// grpc listener
	grpcListener, err := net.Listen("tcp", config.Global.APIAddress)
	if err != nil {
		panic(err)
	}

	log.Infof("listening: %s", config.Global.APIAddress)
	go func() {
		if err := grpcServer.Serve(grpcListener); err != nil {
			log.Infof("%s", err)
		}
	}()

	// prometheus listener
	metricsListener, err := net.Listen("tcp", config.Global.MetricsAddress)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.Handle(prometheusPath, promhttp.Handler())
	mux.HandleFunc("/healthz", kubeHealth.HandlerFunc())

	httpServer := &http.Server{
		Addr:    config.Global.MetricsAddress,
		Handler: mux,
	}
	if config.Global.TLS.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(config.Global.TLS.CertFile, config.Global.TLS.KeyFile)
		if err != nil {
			panic(err)
		}
		httpServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
		}
		metricsListener = tls.NewListener(metricsListener, httpServer.TLSConfig)
	}

	log.Infof("listening: %s", config.Global.MetricsAddress)
	go func() {
		if err := httpServer.Serve(metricsListener); err != nil {
			log.Infof("%s", err)
		}
	}()

	// watch for termination signals
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)    // terminal
		signal.Notify(sigint, syscall.SIGTERM) // kubernetes
		sig := <-sigint
		log.Infof("shutdown signal: %s", sig)
		signal.Stop(sigint)

		grpcServer.GracefulStop()

		timeout, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := httpServer.Shutdown(timeout); err != nil {
			log.Errorf("http shutdown: %v", err)
		}
		cancel()

		rsHandler.Close()

		log.Infof("shutdown complete")
		os.Exit(0)
	}()
}
