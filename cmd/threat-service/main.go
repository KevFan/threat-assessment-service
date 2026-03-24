package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/kuadrant/threat-assessment-service/internal/scoring"
	"github.com/kuadrant/threat-assessment-service/internal/server"
	threatv1 "github.com/kuadrant/threat-assessment-service/pkg/threat/v1"
)

const defaultAddr = ":8080"

func main() {
	addr := os.Getenv("GRPC_ADDR")
	if addr == "" {
		addr = defaultAddr
	}

	scorer := scoring.NewScorer(loadBlacklist())

	grpcServer := grpc.NewServer()
	threatv1.RegisterThreatAssessmentServiceServer(grpcServer, server.New(scorer))

	healthSrv := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthSrv)
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus("threat.v1.ThreatAssessmentService", healthpb.HealthCheckResponse_SERVING)

	// gRPC Server Reflection — required for Extension SDK dynamic proto discovery
	reflection.Register(grpcServer)

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("failed to listen", "addr", addr, "error", err)
		os.Exit(1)
	}

	slog.Info("threat assessment service starting", "addr", addr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			slog.Error("gRPC server error", "error", err)
		}
	}()

	<-quit
	slog.Info("shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		slog.Info("server stopped")
	case <-ctx.Done():
		slog.Warn("graceful shutdown timed out, forcing stop")
		grpcServer.Stop()
	}
}

// loadBlacklist reads IPs from BLACKLIST_IPS env var or BLACKLIST_FILE path.
func loadBlacklist() []string {
	if raw := os.Getenv("BLACKLIST_IPS"); raw != "" {
		return splitIPs(raw)
	}

	path := os.Getenv("BLACKLIST_FILE")
	if path == "" {
		path = "/etc/threat-service/blacklist/ips"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("could not read blacklist file", "path", path, "error", err)
		}
		return nil
	}

	return splitIPs(string(data))
}

func splitIPs(raw string) []string {
	raw = strings.ReplaceAll(raw, ",", "\n")
	lines := strings.Split(raw, "\n")
	var out []string
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
