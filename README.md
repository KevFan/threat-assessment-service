# ThreatAssessmentService

A mock gRPC service that evaluates HTTP requests and returns a threat level score (0–10).
Used by the ThreatPolicy extension via wasm-shim to demonstrate the Extension SDK's dynamic service orchestration capabilities.

## Proto Interface

```protobuf
service ThreatAssessmentService {
  rpc AssessRequest(ThreatRequest) returns (ThreatResponse);
}
```

## Scoring Rules

| Rule | Condition | Points |
|------|-----------|--------|
| Unauthenticated | `is_authenticated = false` | +1 |
| Blacklisted IP | source IP in blacklist | +5 |
| Path traversal | URI contains `../` or `..\` | +4 |
| Admin without auth | URI starts with `/admin` and not authenticated | +3 |

**Threat Level Scale:** 0–2 Low · 3–5 Medium · 6+ High

## Running Locally

```bash
go run ./cmd/threat-service
```

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `GRPC_ADDR` | `:8080` | Listen address |
| `BLACKLIST_FILE` | `/etc/threat-service/blacklist/ips` | Path to newline-separated IP list |
| `BLACKLIST_IPS` | _(unset)_ | Comma- or newline-separated IPs (overrides file) |

## Building the Docker Image

```bash
docker build -t threat-assessment-service:latest .
```

## Deploying to Kubernetes

### Standard cluster

```bash
kubectl create namespace security
kubectl apply -f examples/threatpolicy/threat-service/configmap.yaml
kubectl apply -f examples/threatpolicy/threat-service/deployment.yaml
kubectl apply -f examples/threatpolicy/threat-service/service.yaml
```

### kind cluster

kind does not pull images from the local Docker daemon, so load the image into the cluster first:

```bash
kind load docker-image threat-assessment-service:latest

kubectl create namespace security
kubectl apply -f examples/threatpolicy/threat-service/configmap.yaml
kubectl apply -f examples/threatpolicy/threat-service/deployment.yaml
kubectl apply -f examples/threatpolicy/threat-service/service.yaml
```

## Testing with grpcurl

```bash
# Port-forward the service
kubectl port-forward -n security svc/threat-assessment-service 8080:8080

# List services (uses gRPC reflection)
grpcurl -plaintext localhost:8080 list

# Clean request — threat_level: 0
grpcurl -plaintext -d '{"uri": "/users", "is_authenticated": true, "source_ip": "10.0.0.1"}' \
  localhost:8080 threat.v1.ThreatAssessmentService/AssessRequest

# Unauthenticated admin — threat_level: 4
grpcurl -plaintext -d '{"uri": "/admin", "is_authenticated": false, "source_ip": "10.0.0.1"}' \
  localhost:8080 threat.v1.ThreatAssessmentService/AssessRequest

# Blacklisted IP, unauthenticated — threat_level: 6
grpcurl -plaintext -d '{"uri": "/users", "is_authenticated": false, "source_ip": "192.0.2.100"}' \
  localhost:8080 threat.v1.ThreatAssessmentService/AssessRequest
```

## Running Tests

Unit tests:

```bash
go test ./...
```

Integration tests (requires `grpcurl`):

```bash
make integration-test
```
