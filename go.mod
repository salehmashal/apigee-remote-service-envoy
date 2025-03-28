module github.com/apigee/apigee-remote-service-envoy/v2

go 1.22

toolchain go1.23.5

replace github.com/apigee/apigee-remote-service-golib/v2 => ../apigee-remote-service-golib

require (
	github.com/apigee/apigee-remote-service-golib/v2 v2.1.3
	github.com/envoyproxy/go-control-plane/envoy v1.32.3
	github.com/gogo/googleapis v1.4.1
	github.com/golang/protobuf v1.5.4
	github.com/google/go-cmp v0.6.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/lestrrat-go/jwx v1.1.6
	github.com/oliveagle/jsonpath v0.0.0-20180606110733-2e52cf6e6852
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.12.1
	github.com/spf13/cobra v1.1.3
	go.uber.org/zap v1.16.0
	golang.org/x/oauth2 v0.22.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240814211410-ddb44dafa142
	google.golang.org/grpc v1.67.1
	google.golang.org/protobuf v1.35.2
	gopkg.in/yaml.v3 v3.0.1
)

require (
	cloud.google.com/go/compute/metadata v0.5.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cncf/xds/go v0.0.0-20240723142845-024c85f92f20 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v3 v3.0.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.1.0 // indirect
	github.com/goccy/go-json v0.4.8 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/httpcc v1.0.0 // indirect
	github.com/lestrrat-go/iter v1.0.1 // indirect
	github.com/lestrrat-go/option v1.0.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/prometheus/client_model v0.6.0 // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
