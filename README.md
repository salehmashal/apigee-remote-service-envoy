[![Build](https://github.com/apigee/apigee-remote-service-envoy/workflows/Build/badge.svg)](https://github.com/apigee/apigee-remote-service-envoy/workflows/Build/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/apigee/apigee-remote-service-envoy)](https://goreportcard.com/report/github.com/apigee/apigee-remote-service-envoy)
[![codecov.io](https://codecov.io/github/apigee/apigee-remote-service-envoy/coverage.svg?)](https://codecov.io/github/apigee/apigee-remote-service-envoy)
[![In Solidarity](https://github.com/jpoehnelt/in-solidarity-bot/raw/main/static/badge-flat.png)](https://github.com/apps/in-solidarity)


# [Custom] Apigee Remote Service for Envoy

This project exposes standard Envoy gRPC endpoints for the `External Authorization (ext-authz)`, `External Processing (ext-proc) for llm token quota` 
and `gRPC Access Log Service (ALS)` interfaces. Thus, it allows Envoy to be used as a limited
remote API Gateway extension to an Apigee environment. Features directly supported include:
authentication and authorization via API Key or JWT OAuth Tokens, Distributed Quota, and Analytics.

Health check and prometheus management endpoints are also exposed.

See [releases](https://github.com/apigee/apigee-remote-service-envoy/releases) for current binary and docker images.

## Getting Started

There is specific documentation for your Apigee platform:

* [Apigee Edge on Google Cloud or Hybrid](https://cloud.google.com/apigee/docs/api-platform/envoy-adapter/latest/concepts)
* [Classic Apigee Edge](https://docs.apigee.com/api-platform/envoy-adapter)

## Support

Issues filed on Github are not subject to service level agreements (SLAs) and responses should be
assumed to be on an ad-hoc volunteer basis. The [Apigee community board](https://community.apigee.com/)
is recommended as for community support and is regularly checked by Apigee experts.

Apigee customers should use [formal support channels](https://cloud.google.com/apigee/support).
