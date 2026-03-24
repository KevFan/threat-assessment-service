package server

import (
	"context"
	"log/slog"

	"github.com/kuadrant/threat-assessment-service/internal/scoring"
	threatv1 "github.com/kuadrant/threat-assessment-service/pkg/threat/v1"
)

// ThreatServer implements the ThreatAssessmentService gRPC interface.
type ThreatServer struct {
	threatv1.UnimplementedThreatAssessmentServiceServer
	scorer *scoring.Scorer
}

// New creates a ThreatServer backed by the given Scorer.
func New(scorer *scoring.Scorer) *ThreatServer {
	return &ThreatServer{scorer: scorer}
}

func (s *ThreatServer) AssessRequest(ctx context.Context, req *threatv1.ThreatRequest) (*threatv1.ThreatResponse, error) {
	level, reasons := s.scorer.Score(req.Uri, req.IsAuthenticated, req.SourceIp)

	slog.Info("assessed request",
		"uri", req.Uri,
		"is_authenticated", req.IsAuthenticated,
		"source_ip", req.SourceIp,
		"threat_level", level,
		"reasons", reasons,
	)

	return &threatv1.ThreatResponse{
		ThreatLevel: level,
		Reasons:     reasons,
	}, nil
}
