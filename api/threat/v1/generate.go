//go:generate protoc --go_out=../../../ --go_opt=module=github.com/kuadrant/threat-assessment-service --go-grpc_out=../../../ --go-grpc_opt=module=github.com/kuadrant/threat-assessment-service threat.proto

package threatv1
