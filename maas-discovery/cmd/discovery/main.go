package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/opendatahub-io/models-as-a-service/maas-discovery/internal/cache"
	"github.com/opendatahub-io/models-as-a-service/maas-discovery/internal/cert"
	"github.com/opendatahub-io/models-as-a-service/maas-discovery/internal/handler"
)

const shutdownTimeout = 15 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", ":8443", "listen address")
	tlsCert := flag.String("tls-cert", "", "path to TLS certificate file")
	tlsKey := flag.String("tls-key", "", "path to TLS key file")
	selfSigned := flag.Bool("self-signed", false, "generate a self-signed certificate for development")
	kubeconfig := flag.String("kubeconfig", "", "path to kubeconfig file (out-of-cluster only)")
	tenantNamespace := flag.String("aitenant-namespace", "ai-tenants", "namespace where AITenant CRs are created")
	gatewayNamespace := flag.String("gateway-namespace", "openshift-ingress", "namespace of Gateway resources")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	tlsConfig, err := buildTLSConfig(*tlsCert, *tlsKey, *selfSigned)
	if err != nil {
		return fmt.Errorf("configuring TLS: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := buildCache(ctx, log, *kubeconfig, *tenantNamespace, *gatewayNamespace)
	if err != nil {
		return fmt.Errorf("creating cache: %w", err)
	}

	h := handler.New(tc)

	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())
	h.RegisterRoutes(engine)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           engine,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("starting discovery service", "addr", *addr)
		if serr := srv.ListenAndServeTLS("", ""); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			errCh <- serr
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Info("shutting down", "signal", sig.String())
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}
	log.Info("server stopped")
	return nil
}

//nolint:ireturn // returns Stub or InformerCache depending on environment
func buildCache(ctx context.Context, log *slog.Logger, kubeconfig, tenantNS, gatewayNS string) (cache.TenantCache, error) {
	restConfig, err := getRestConfig(kubeconfig)
	if err != nil {
		log.Warn("no kubeconfig available, using stub cache for development", "error", err)
		return cache.NewStub(), nil
	}

	ic, err := cache.NewInformerCache(cache.InformerCacheOptions{
		RestConfig:       restConfig,
		TenantNamespace:  tenantNS,
		GatewayNamespace: gatewayNS,
		Log:              log,
	})
	if err != nil {
		return nil, fmt.Errorf("creating informer cache: %w", err)
	}

	go func() {
		if serr := ic.Start(ctx); serr != nil {
			log.Error("informer cache error", "error", serr)
		}
	}()

	return ic, nil
}

func getRestConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
	}
	return cfg, nil
}

func buildTLSConfig(certFile, keyFile string, selfSigned bool) (*tls.Config, error) {
	var tlsCert tls.Certificate
	var err error

	switch {
	case certFile != "" && keyFile != "":
		tlsCert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading TLS certificate: %w", err)
		}
	case selfSigned:
		tlsCert, err = cert.Generate("maas-discovery")
		if err != nil {
			return nil, fmt.Errorf("generating self-signed certificate: %w", err)
		}
	default:
		return nil, errors.New("TLS is required: provide --tls-cert and --tls-key, or use --self-signed for development")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}
