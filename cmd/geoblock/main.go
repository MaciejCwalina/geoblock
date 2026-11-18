// Command geoblock captures IPv4 traffic on one interface, resolves the
// country of every remote peer, drops traffic from blocked countries with
// iptables and exports traffic counters for Prometheus.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"

	"github.com/MaciejCwalina/go_prometheus_packet_monitoring/internal/capture"
	"github.com/MaciejCwalina/go_prometheus_packet_monitoring/internal/config"
	"github.com/MaciejCwalina/go_prometheus_packet_monitoring/internal/firewall"
	"github.com/MaciejCwalina/go_prometheus_packet_monitoring/internal/geo"
	"github.com/MaciejCwalina/go_prometheus_packet_monitoring/internal/metrics"
	"github.com/MaciejCwalina/go_prometheus_packet_monitoring/internal/monitor"
	"github.com/MaciejCwalina/go_prometheus_packet_monitoring/internal/netclass"
)

// memoryCacheEntries bounds the in-process cache (roughly 100 bytes each).
const memoryCacheEntries = 100_000

func main() {
	defaultConfigPath, err := config.DefaultPath()
	if err != nil {
		defaultConfigPath = "config.json"
	}
	configPath := flag.String("config", defaultConfigPath, "path to the JSON config file")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn or error")
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "invalid -log-level %q\n", *logLevel)
		os.Exit(2)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	settings, err := config.Load(*configPath)
	if errors.Is(err, config.ErrExampleWritten) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", *configPath, err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err = run(ctx, settings, logger)
	stop()
	if err != nil {
		logger.Error("exiting", "error", err)
		os.Exit(1)
	}
	logger.Info("stopped")
}

func run(ctx context.Context, settings config.Config, logger *slog.Logger) error {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	exporter := metrics.New(registry)

	redisClient := redis.NewClient(&redis.Options{
		Addr:     settings.RedisDataBaseAddress,
		Password: settings.RedisPassword,
	})
	defer func() {
		if err := redisClient.Close(); err != nil {
			logger.Warn("closing redis client", "error", err)
		}
	}()
	pingContext, cancelPing := context.WithTimeout(ctx, 3*time.Second)
	if err := redisClient.Ping(pingContext).Err(); err != nil {
		logger.Warn("redis is unreachable, lookups will go straight to the API until it is back",
			"address", settings.RedisDataBaseAddress, "error", err)
	}
	cancelPing()

	blocker, err := newFirewall(settings, logger)
	if err != nil {
		return err
	}

	localAddresses, err := interfaceAddresses(settings.InterfaceName)
	if err != nil {
		return err
	}
	filter, err := captureFilter(ctx, settings)
	if err != nil {
		return err
	}

	cacheTTL := time.Duration(settings.RedisCacheTTL)
	resolver := geo.NewResolver(
		geo.NewMemoryCache(memoryCacheEntries, cacheTTL),
		geo.NewRedisCache(redisClient, cacheTTL),
		geo.NewIPAPIClient(settings.LookupBaseURL, settings.LookupRequestsPerMinute),
		func(source geo.Source, result geo.Result) {
			exporter.ObserveLookup(string(source), string(result))
		},
		logger,
	)
	packetMonitor := monitor.New(
		netclass.NewClassifier(localAddresses),
		resolver,
		blocker,
		monitor.NewPolicy(settings.ListOfBlockedCountryCodes),
		exporter,
		logger,
		monitor.Options{},
	)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		packetMonitor.Run(ctx)
	}()

	server := newHTTPServer(settings.ListenAddress, registry)
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("serving metrics", "address", settings.ListenAddress)
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
		close(serverErrors)
	}()

	captureErrors := make(chan error, 1)
	go func() {
		logger.Info("capturing", "interface", settings.InterfaceName, "filter", filter,
			"blocked_countries", settings.ListOfBlockedCountryCodes, "dry_run", settings.DryRun)
		captureErrors <- capture.Run(ctx, settings.InterfaceName, filter, packetMonitor.HandlePacket)
	}()

	var runErr error
	captureFinished := false
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-serverErrors:
		runErr = fmt.Errorf("metrics server: %w", err)
	case err := <-captureErrors:
		captureFinished = true
		if err == nil {
			err = errors.New("capture stopped unexpectedly")
		}
		runErr = fmt.Errorf("capture: %w", err)
	}
	cancel()

	if !captureFinished {
		// Wait for the capture loop to notice cancellation and close the
		// pcap handle.
		if err := <-captureErrors; err != nil {
			logger.Warn("capture stopped with error", "error", err)
		}
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownContext); err != nil {
		logger.Warn("metrics server shutdown", "error", err)
	}
	<-monitorDone
	return runErr
}

func newHTTPServer(listenAddress string, registry *prometheus.Registry) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
	return &http.Server{
		Addr:              listenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func newFirewall(settings config.Config, logger *slog.Logger) (firewall.Firewall, error) {
	if settings.DryRun {
		return firewall.NewDryRun(logger), nil
	}
	rules, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4))
	if err != nil {
		return nil, fmt.Errorf("iptables: %w", err)
	}
	return firewall.NewIPTables(rules), nil
}

// interfaceAddresses lists the IPv4 addresses assigned to interfaceName.
func interfaceAddresses(interfaceName string) ([]netip.Addr, error) {
	networkInterface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", interfaceName, err)
	}
	interfaceAddresses, err := networkInterface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("addresses of %q: %w", interfaceName, err)
	}
	var addresses []netip.Addr
	for _, interfaceAddress := range interfaceAddresses {
		prefix, err := netip.ParsePrefix(interfaceAddress.String())
		if err != nil {
			continue
		}
		if address := prefix.Addr().Unmap(); address.Is4() {
			addresses = append(addresses, address)
		}
	}
	return addresses, nil
}

// captureFilter resolves the Redis and lookup API endpoints and returns a BPF
// filter that excludes their traffic.
func captureFilter(ctx context.Context, settings config.Config) (string, error) {
	redisHost, redisPort, err := net.SplitHostPort(settings.RedisDataBaseAddress)
	if err != nil {
		return "", fmt.Errorf("RedisDataBaseAddress %q: %w", settings.RedisDataBaseAddress, err)
	}
	lookupURL, err := url.Parse(settings.LookupBaseURL)
	if err != nil {
		return "", fmt.Errorf("LookupBaseURL: %w", err)
	}
	lookupPort := lookupURL.Port()
	if lookupPort == "" {
		lookupPort = map[string]string{"http": "80", "https": "443"}[lookupURL.Scheme]
	}

	var excluded []capture.Endpoint
	for _, service := range []struct{ host, port string }{
		{redisHost, redisPort},
		{lookupURL.Hostname(), lookupPort},
	} {
		endpoints, err := resolveEndpoints(ctx, service.host, service.port)
		if err != nil {
			return "", err
		}
		excluded = append(excluded, endpoints...)
	}
	return capture.BuildFilter(excluded), nil
}

func resolveEndpoints(ctx context.Context, host, port string) ([]capture.Endpoint, error) {
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("port %q: %w", port, err)
	}
	resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	endpoints := make([]capture.Endpoint, 0, len(resolved))
	for _, address := range resolved {
		endpoints = append(endpoints, capture.Endpoint{Address: address, Port: uint16(portNumber)})
	}
	return endpoints, nil
}
