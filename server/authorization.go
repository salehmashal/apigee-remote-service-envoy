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

package server

import (
	gocontext "context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oliveagle/jsonpath"

	"github.com/apigee/apigee-remote-service-golib/v2/analytics"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/apigee/apigee-remote-service-golib/v2/quota"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

const (
	jwtFilterMetadataKey = "envoy.filters.http.jwt_authn"
	envContextKey        = "apigee_environment"
	apiContextKey        = "apigee_api"
)

// AuthorizationServer server
type AuthorizationServer struct {
	handler *Handler
}

type AuthorizedOperation struct {
	ID            string
	QuotaLimit    int64
	QuotaInterval int64
	QuotaTimeUnit string
	APIProduct    string
}

// stringToInt converts a string to an int64
func stringToInt(s string) int64 {
	value, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		// Handle the error (e.g., log it or return a default value)
		return 0 // Default value in case of error
	}
	return value
}

// Register registers
func (a *AuthorizationServer) Register(s *grpc.Server, handler *Handler) {
	envoy_auth.RegisterAuthorizationServer(s, a)
	a.handler = handler
}

// Check if it is the response of the request flow.
func isResponseFlow(req *envoy_auth.CheckRequest) bool {
	// If Envoy calls ext_authz after it has an upstream response, it may set "X-Envoy-Original-Path"
	// or "x-envoy-original-method" or some other header to indicate the response flow.
	if _, ok := req.Attributes.Request.Http.Headers["x-envoy-original-path"]; ok {
		return true
	}

	// Another heuristic: If the request method is empty or :status is present
	if req.Attributes.Request.Http.Method == "" &&
		req.Attributes.Request.Http.Headers[":status"] != "" {
		return true
	}

	return false
}

// Check does check
func (a *AuthorizationServer) Check(ctx gocontext.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {

	var rootContext context.Context = a.handler
	var err error
	envFromEnvoy, envFromEnvoyExists := req.Attributes.ContextExtensions[envContextKey]
	if a.handler.isMultitenant {
		if envFromEnvoyExists && envFromEnvoy != "" {
			rootContext = &multitenantContext{
				a.handler,
				envFromEnvoy,
			}
		} else {
			err = fmt.Errorf("no %s metadata for multi-tentant mode", envContextKey)
		}
	} else if envFromEnvoyExists && envFromEnvoy != rootContext.Environment() {
		err = fmt.Errorf("%s metadata (%s) disallowed when not in multi-tentant mode", envContextKey, rootContext.Environment())
	}

	tracker := prometheusRequestTracker(rootContext)
	defer tracker.record()

	if err != nil {
		return a.internalError(req, tracker, nil, "", err), nil
	}

	var api string
	if v, ok := req.Attributes.ContextExtensions[apiContextKey]; ok { // api specified in context metadata
		api = v
	} else {
		api, ok = req.Attributes.Request.Http.Headers[a.handler.apiHeader]
		if !ok {
			log.Debugf("missing api header %s", a.handler.apiHeader)
			return a.unauthorized(req, tracker, nil, ""), nil
		}
	}

	// check for JWT from Envoy filter
	protoBufStruct := req.Attributes.GetMetadataContext().GetFilterMetadata()[jwtFilterMetadataKey]
	fieldsMap := protoBufStruct.GetFields()
	var claims map[string]interface{}

	// use jwtProviderKey check if jwtProviderKey is set in config
	if a.handler.jwtProviderKey != "" {
		claimsStruct, ok := fieldsMap[a.handler.jwtProviderKey]
		if ok {
			log.Debugf("Using JWT at provider key: %s", a.handler.jwtProviderKey)
			claims = DecodeToMap(claimsStruct.GetStructValue())
		}
	} else { // otherwise iterate over apiKeyClaim loop
		for k, v := range fieldsMap {
			vFields := v.GetStructValue().GetFields()
			if vFields[a.handler.apiKeyClaim] != nil || vFields["api_product_list"] != nil {
				log.Debugf("Using JWT with provider key: %s", k)
				claims = DecodeToMap(v.GetStructValue())
			}
		}
	}

	splitPath := strings.SplitN(req.Attributes.Request.Http.Path, "?", 2)
	path := splitPath[0]

	apiKey, ok := req.Attributes.Request.Http.Headers[a.handler.apiKeyHeader] // grab from header

	if !ok && len(splitPath) > 1 { // look in querystring if not in header
		if qs, err := url.ParseQuery(splitPath[1]); err == nil {
			if keys, ok := qs[a.handler.apiKeyHeader]; ok {
				apiKey = keys[0]
			}
		}
	}
	authContext, err := a.handler.authMan.Authenticate(rootContext, apiKey, claims, a.handler.apiKeyClaim)
	switch err {
	case auth.ErrNoAuth:
		return a.unauthorized(req, tracker, authContext, api), nil
	case auth.ErrBadAuth:
		return a.denied(req, tracker, authContext, api), nil
	case auth.ErrInternalError:
		return a.internalError(req, tracker, authContext, api, err), nil
	}

	if len(authContext.APIProducts) == 0 {
		return a.denied(req, tracker, authContext, api), nil
	}
	// authorize against products
	method := req.Attributes.Request.Http.Method
	authorizedOps := a.handler.productMan.Authorize(authContext, api, path, method)
	if len(authorizedOps) == 0 {
		return a.denied(req, tracker, authContext, api), nil
	}
	authContext.AnalyticsProduct = authorizedOps[0].APIProduct

	// fmt.Printf("Authorized API Products: %+v\nAPI Products Custom Attribute : %+v\n", authorizedOps, a.handler.productMan.Products()[authorizedOps[0].APIProduct].Attributes)
	// fmt.Printf("Authorized Operations %+v", authorizedOps)
	//LLM Token Quotas
	productDetails := a.handler.productMan.Products()[authorizedOps[0].APIProduct]
	var llmQuotaEnabled = false
	var llmQuotaLimit int64 = 0
	var llmQuotaInterval int64 = 0
	var llmQuotaTimeUnit string
	var llmOp product.AuthorizedOperation
	var llmQuotaArgs quota.Args
	var llmTokenExceeded bool
	var llmTokenAnyError error
	var llmQuotaUsageLocation string
	var llmTokenUsageHeaderName string
	var llmTokenUsagePayloadJsonPath string
	var llmQuotaLimitClassClaim string = "entitlements"
	var apiProductKeys map[string]int

	llmQuotaId := "llm-token-" + authorizedOps[0].APIProduct + "-" + authContext.Environment() + "--" + authContext.Application
	apiProductKeys = make(map[string]int)
	//Check the llm quota is enabled on the Api product
	for i, attr := range productDetails.Attributes {
		apiProductKeys[attr.Name] = i + 1
		switch attr.Name {
		case "llm-quota-enabled":
			llmQuotaEnabled = attr.Value == "true"
		case "llm-quota-limit":
			llmQuotaLimit = stringToInt(attr.Value)
		case "llm-quota-interval":
			llmQuotaInterval = stringToInt(attr.Value)
		case "llm-quota-time-unit":
			llmQuotaTimeUnit = attr.Value
		case "llm-token-usage-header-name":
			llmTokenUsageHeaderName = attr.Value
		case "llm-token-usage-payload-json-path":
			llmTokenUsagePayloadJsonPath = attr.Value
		case "llm-quota-usage-location":
			llmQuotaUsageLocation = attr.Value
			if llmQuotaUsageLocation != "header" && llmQuotaUsageLocation != "payload" {
				log.Errorf("`llm-quota-usage-location` custom attribute has an invalid value: %+v, please make sure to provide the location of the llm token usage header or payload", llmQuotaUsageLocation)
				return a.internalError(req, tracker, authContext, api, llmTokenAnyError), nil
			}
		case "llm-quota-limit-class-claim":
			llmQuotaLimitClassClaim = attr.Value
		}

	}

	if llmQuotaEnabled {
		log.Infof("llm quota is enabled for the product: %+v", productDetails.Name)
		maxLimit := 0
		// check if the limit-class-claim is present in jwt metadata
		var claims map[string]interface{}
		protoBufStruct := req.Attributes.GetMetadataContext().GetFilterMetadata()[jwtFilterMetadataKey]
		fieldsMap := protoBufStruct.GetFields()

		if a.handler.jwtProviderKey != "" {
			claimsStruct, ok := fieldsMap[a.handler.jwtProviderKey]
			if ok {
				log.Debugf("Using JWT at provider key: %s", a.handler.jwtProviderKey)
				claims = DecodeToMap(claimsStruct.GetStructValue())
			}
		} else {
			for k, v := range fieldsMap {
				vFields := v.GetStructValue().GetFields()
				if vFields[a.handler.apiKeyClaim] != nil || vFields["api_product_list"] != nil {
					log.Debugf("Using JWT with provider key: %s", k)
					claims = DecodeToMap(v.GetStructValue())
				}
			}
		}
		if claims != nil {
			if _, ok := claims[llmQuotaLimitClassClaim]; ok {
				//retrieve the array of values
				classes, ok := claims[llmQuotaLimitClassClaim].([]interface{})
				if !ok {
					log.Warnf("llmQuotaLimitClassClaim: %s is not an array of string in JWT claims", llmQuotaLimitClassClaim)
				} else {
					for _, class := range classes {
						className, ok := class.(string)
						if !ok {
							log.Warnf("llmQuotaLimitClassClaim: %s value is not a string: %v", llmQuotaLimitClassClaim, class)
							continue
						}

						if apiProductKeys["llm-quota-"+className+"-limit"] > 0 {
							index := apiProductKeys["llm-quota-"+className+"-limit"] - 1
							limit := productDetails.Attributes[index].Value
							if stringToInt(limit) > int64(maxLimit) {
								maxLimit = int(stringToInt(limit))
							}
						}
					}
				}
			}
		} else {
			log.Warnf("Unable to retrieve claims")
		}
		llmQuotaLimit = int64(maxLimit)
		//check if pre-check or deduct
		if isResponseFlow(req) {
			fmt.Print("test1")
			var llmTokensConsumed int64

			if llmQuotaUsageLocation == "" {
				log.Errorf("`llm-quota-usage-location` custom attribute has an invalid value or not set: %+v, please make sure to provide the location of the llm token usage header or payload", llmQuotaUsageLocation)
				return a.internalError(req, tracker, authContext, api, llmTokenAnyError), nil
			} else {
				if llmTokenUsagePayloadJsonPath == "" && llmQuotaUsageLocation == "payload" {
					log.Errorf("`llm-token-usage-payload-json-path` custom attribute is not set please make sure to set the correct json path")
					return a.internalError(req, tracker, authContext, api, llmTokenAnyError), nil
				} else if llmQuotaUsageLocation == "payload" {
					if req.Attributes.Request.Http.Body == "" {
						log.Errorf("`llm-token-usage-payload-json-path` body is empty")
						llmTokensConsumed = 1
					} else {
						var data interface{}
						err := json.Unmarshal([]byte(req.Attributes.Request.Http.Body), &data)
						if err != nil {
							log.Errorf("Failed to unmarshal request body: %v", err)
							llmTokensConsumed = 1
						} else {
							res, err := jsonpath.JsonPathLookup(data, llmTokenUsagePayloadJsonPath)
							if err != nil {
								log.Errorf("Error extracting data from JSON payload using path %s: %v", llmTokenUsagePayloadJsonPath, err)
								llmTokensConsumed = 1
							} else {
								if val, ok := res.(float64); ok {
									llmTokensConsumed = int64(val)
								} else if val, ok := res.(int64); ok {
									llmTokensConsumed = val
								} else if val, ok := res.(int); ok {
									llmTokensConsumed = int64(val)
								} else if val, ok := res.(string); ok {
									llmTokensConsumed = stringToInt(val)
								} else {
									log.Errorf("`llm-token-usage-payload-json-path` custom attribute has an invalid value: %+v, please make sure to provide a value compatible with integer", res)
									llmTokensConsumed = 1
								}
							}
						}
					}

				}
				if llmTokenUsageHeaderName == "" && llmQuotaUsageLocation == "header" {
					log.Errorf("`llm-token-usage-header-name` custom attribute is not set please make sure to set the correct header name")
					return a.internalError(req, tracker, authContext, api, llmTokenAnyError), nil
				} else if llmQuotaUsageLocation == "header" && llmTokenUsageHeaderName != "" {
					if req.Attributes.Request.Http.Headers[llmTokenUsageHeaderName] != "" {
						llmTokensConsumed = stringToInt(req.Attributes.Request.Http.Headers[llmTokenUsageHeaderName])
					} else {
						llmTokensConsumed = 1
					}
				}
			}

			llmQuotaArgs = quota.Args{QuotaAmount: llmTokensConsumed}

		} else {
			//Pass the weight of the request to zero just to check the quota is exceeded or not
			llmQuotaArgs = quota.Args{QuotaAmount: 0}
		}
		llmOp = product.AuthorizedOperation{
			ID:            llmQuotaId,
			APIProduct:    authorizedOps[0].APIProduct,
			QuotaLimit:    llmQuotaLimit,
			QuotaInterval: llmQuotaInterval,
			QuotaTimeUnit: llmQuotaTimeUnit,
		}
		if llmOp.QuotaLimit > 0 {
			result, err := a.handler.quotaMan.Apply(authContext, llmOp, llmQuotaArgs)
			if err != nil {
				log.Errorf("llm token quota check: %v", err)
				llmTokenAnyError = err
			} else if result.Exceeded > 0 {
				log.Debugf("llm token quota exceeded: %v", llmOp.ID)
				llmTokenExceeded = true
			}
		}

		if llmTokenAnyError != nil {
			return a.internalError(req, tracker, authContext, api, llmTokenAnyError), nil
		}
		if llmTokenExceeded {
			return a.quotaExceeded(req, tracker, authContext, api), nil
		}
	}
	// apply quotas to matched operations
	var exceeded bool
	var anyError error
	var quotaArgs = quota.Args{QuotaAmount: 1}
	for _, op := range authorizedOps {
		if op.QuotaLimit > 0 {
			result, err := a.handler.quotaMan.Apply(authContext, op, quotaArgs)
			if err != nil {
				log.Errorf("quota check: %v", err)
				anyError = err
			} else if result.Exceeded > 0 {
				log.Debugf("quota exceeded: %v", op.ID)
				exceeded = true
			}
		}
	}
	if anyError != nil {
		return a.internalError(req, tracker, authContext, api, anyError), nil
	}
	if exceeded {
		return a.quotaExceeded(req, tracker, authContext, api), nil
	}

	return a.authOK(tracker, authContext, api), nil
}

func (a *AuthorizationServer) authOK(tracker *prometheusRequestMetricTracker, authContext *auth.Context, api string) *envoy_auth.CheckResponse {

	okResponse := &envoy_auth.OkHttpResponse{}

	if a.handler.appendMetadataHeaders {
		headers := makeMetadataHeaders(api, authContext, true)
		okResponse.Headers = headers
	}

	tracker.statusCode = envoy_type.StatusCode_OK
	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &envoy_auth.CheckResponse_OkResponse{
			OkResponse: okResponse,
		},
		DynamicMetadata: encodeExtAuthzMetadata(api, authContext, true),
	}
}

func (a *AuthorizationServer) unauthorized(req *envoy_auth.CheckRequest, tracker *prometheusRequestMetricTracker, authContext *auth.Context, api string) *envoy_auth.CheckResponse {
	return a.createDenyResponse(req, tracker, authContext, api, rpc.UNAUTHENTICATED)
}

func (a *AuthorizationServer) internalError(req *envoy_auth.CheckRequest, tracker *prometheusRequestMetricTracker, authContext *auth.Context, api string, err error) *envoy_auth.CheckResponse {
	log.Errorf("sending internal error: %v", err)
	return a.createDenyResponse(req, tracker, authContext, api, rpc.INTERNAL)
}

func (a *AuthorizationServer) denied(req *envoy_auth.CheckRequest, tracker *prometheusRequestMetricTracker, authContext *auth.Context, api string) *envoy_auth.CheckResponse {
	return a.createDenyResponse(req, tracker, authContext, api, rpc.PERMISSION_DENIED)
}

func (a *AuthorizationServer) quotaExceeded(req *envoy_auth.CheckRequest, tracker *prometheusRequestMetricTracker, authContext *auth.Context, api string) *envoy_auth.CheckResponse {
	return a.createDenyResponse(req, tracker, authContext, api, rpc.RESOURCE_EXHAUSTED)
}

func (a *AuthorizationServer) createDenyResponse(req *envoy_auth.CheckRequest, tracker *prometheusRequestMetricTracker, authContext *auth.Context, api string, code rpc.Code) *envoy_auth.CheckResponse {

	// use intended code, not OK
	switch code {
	case rpc.UNAUTHENTICATED:
		tracker.statusCode = envoy_type.StatusCode_Unauthorized

	case rpc.INTERNAL:
		tracker.statusCode = envoy_type.StatusCode_InternalServerError

	case rpc.PERMISSION_DENIED:
		tracker.statusCode = envoy_type.StatusCode_Forbidden

	case rpc.RESOURCE_EXHAUSTED:
		tracker.statusCode = envoy_type.StatusCode_TooManyRequests
	}

	if authContext == nil || !a.handler.allowUnauthorized { // send reject to client
		log.Debugf("sending denied: %s", code.String())

		response := &envoy_auth.CheckResponse{
			Status: &rpcstatus.Status{
				Code: int32(code),
			},
			// Envoy won't deliver this, so commenting it out for now. See below.
			// DynamicMetadata: encodeExtAuthzMetadata(api, authContext, false),
		}

		// Envoy automatically maps the other response status codes,
		// but not the RESOURCE_EXHAUSTED status, so we force it.
		if code == rpc.RESOURCE_EXHAUSTED {
			response.HttpResponse = &envoy_auth.CheckResponse_DeniedResponse{
				DeniedResponse: &envoy_auth.DeniedHttpResponse{
					Status: &envoy_type.HttpStatus{
						Code: tracker.statusCode,
					},
				},
			}
		}

		// Envoy does not send metadata to ALS on a reject, so we create the
		// analytics record here and the ALS handler can ignore the metadataless record.
		if api != "" && authContext != nil {
			start := req.Attributes.Request.Time.AsTime().UnixNano() / 1000000
			duration := time.Now().Unix() - tracker.startTime.Unix()
			sent := start + duration                                                   // use Envoy's start time to calculate
			requestPath := strings.SplitN(req.Attributes.Request.Http.Path, "?", 2)[0] // Apigee doesn't want query params in requestPath
			record := analytics.Record{
				ClientReceivedStartTimestamp: start,
				ClientReceivedEndTimestamp:   start,
				TargetSentStartTimestamp:     0,
				TargetSentEndTimestamp:       0,
				TargetReceivedStartTimestamp: 0,
				TargetReceivedEndTimestamp:   0,
				ClientSentStartTimestamp:     sent,
				ClientSentEndTimestamp:       sent,
				APIProxy:                     api,
				RequestURI:                   req.Attributes.Request.Http.Path,
				RequestPath:                  requestPath,
				RequestVerb:                  req.Attributes.Request.Http.Method,
				UserAgent:                    req.Attributes.Request.Http.Headers["User-Agent"],
				ResponseStatusCode:           int(tracker.statusCode),
				GatewaySource:                gatewaySource,
				ClientIP:                     req.Attributes.Request.Http.Headers["X-Forwarded-For"],
			}

			// this may be more efficient to batch, but changing the golib impl would require
			// a rewrite as it assumes the same authContext for all records
			records := []analytics.Record{record}
			err := a.handler.analyticsMan.SendRecords(authContext, records)
			if err != nil {
				log.Warnf("Unable to send ax: %v", err)
			}
		}

		return response
	}

	okResponse := &envoy_auth.OkHttpResponse{}

	if a.handler.appendMetadataHeaders {
		headers := makeMetadataHeaders(api, authContext, false)
		okResponse.Headers = headers
	}

	// allow request to continue upstream
	log.Debugf("sending ok (actual: %s)", code.String())
	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &envoy_auth.CheckResponse_OkResponse{
			OkResponse: okResponse,
		},
		DynamicMetadata: encodeExtAuthzMetadata(api, authContext, false),
	}
}

// prometheus metrics
var (
	prometheusAuthSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Subsystem: "auth",
		Name:      "requests_seconds",
		Help:      "Time taken to process authorization requests by code",
		Buckets:   prometheus.DefBuckets,
	}, []string{"org", "env", "code"})
)

type prometheusRequestMetricTracker struct {
	rootContext context.Context
	startTime   time.Time
	statusCode  envoy_type.StatusCode
}

// set statusCode before calling record()
func prometheusRequestTracker(rootContext context.Context) *prometheusRequestMetricTracker {
	return &prometheusRequestMetricTracker{
		rootContext: rootContext,
		startTime:   time.Now(),
		statusCode:  envoy_type.StatusCode_InternalServerError,
	}
}

// set statusCode before calling
func (t *prometheusRequestMetricTracker) record() {
	codeLabel := fmt.Sprintf("%d", t.statusCode)
	httpDuration := time.Since(t.startTime)
	prometheusAuthSeconds.WithLabelValues(t.rootContext.Organization(), t.rootContext.Environment(), codeLabel).Observe(httpDuration.Seconds())
}

type multitenantContext struct {
	*Handler
	env string
}

func (o *multitenantContext) Environment() string {
	return o.env
}
