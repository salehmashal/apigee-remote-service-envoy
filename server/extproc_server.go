package server

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/apigee/apigee-remote-service-golib/v2/quota"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/oliveagle/jsonpath"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var llmTokensConsumed int64
var llmQuotaUsageLocation string
var llmQuotaArgs quota.Args
var authContext *auth.Context
var llmop product.AuthorizedOperation

type ExtProcServer struct {
	// You might embed references to Handler, etc. if you need data from them.
	handler *Handler
}

// Register your new ExtProcServer on the gRPC server (similar to AccessLog or Authorization).
func (s *ExtProcServer) Register(grpcServer *grpc.Server, handler *Handler) {
	s.handler = handler
	extproc.RegisterExternalProcessorServer(grpcServer, s)
}

// Process implements the stream-based ExternalProcessor service
func (s *ExtProcServer) Process(stream extproc.ExternalProcessor_ProcessServer) error {
	var rootContext context.Context = s.handler
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if status.Code(err) == codes.Canceled {
				log.Infof("ext_proc stream canceled by Envoy: %v", err)
				// End gracefully
				return nil
			}
			// else handle other errors
			log.Errorf("ext_proc stream receive error: %v", err)
			return err
		}
		extAuthzFields := req.MetadataContext.FilterMetadata["envoy.filters.http.ext_authz"].GetFields()
		quotaAttrValue, ok := extAuthzFields["x-apigee-llm-quota-attributes"]
		if !ok {
			log.Errorf("x-apigee-llm-quota-attributes not found in metadata")
			sendInternalErrorResponse(stream)
		}
		quotaAttrStr := quotaAttrValue.GetStringValue()
		var quotaAttrs LLMTokenQuotaAttributes
		if err := json.Unmarshal([]byte(quotaAttrStr), &quotaAttrs); err != nil {
			log.Errorf("Error unmarshalling quota attributes:", err)
			sendInternalErrorResponse(stream)
		}
		authContext, _ = s.handler.authMan.Authenticate(rootContext, quotaAttrs.AuthContextAPIKey, quotaAttrs.AuthContextClaims, s.handler.apiKeyClaim)
		llmop = product.AuthorizedOperation{
			ID:            quotaAttrs.AuthorizedOperation.ID,
			APIProduct:    quotaAttrs.AuthorizedOperation.APIProduct,
			QuotaLimit:    quotaAttrs.AuthorizedOperation.QuotaLimit,
			QuotaInterval: quotaAttrs.AuthorizedOperation.QuotaInterval,
			QuotaTimeUnit: quotaAttrs.AuthorizedOperation.QuotaTimeUnit,
		}
		llmQuotaUsageLocation = quotaAttrs.LlmQuotaUsageLocation
		if quotaAttrs.LlmQuotaEnabled && llmQuotaUsageLocation == "" {
			log.Errorf("`llm-quota-usage-location` custom attribute has an invalid value or not set: %+v, please make sure to provide the location of the llm token usage header or payload", llmQuotaUsageLocation)
			return nil
		}
		switch request := req.Request.(type) {
		case *extproc.ProcessingRequest_ResponseHeaders:
			if llmQuotaUsageLocation == "header" {
				log.Debugf("Processing RESPONSE headers")
				//extract llm token usage from headers
				llmTokenUsageHeaderName := quotaAttrs.LlmTokenUsageHeaderName
				if llmTokenUsageHeaderName == "" {
					log.Errorf("`llm-token-usage-header-name` custom attribute has an invalid value or not set: %+v, please make sure to provide the name of the llm token usage header", llmTokenUsageHeaderName)
					sendInternalErrorResponse(stream)
				}
				responseHeaders := request.ResponseHeaders.GetHeaders().GetHeaders()
				for _, header := range responseHeaders {
					if header.Key == llmTokenUsageHeaderName {
						tokens, err := strconv.ParseInt(string(header.RawValue), 10, 64)
						if err != nil {
							log.Errorf("Failed to parse LLM token usage: %v", err)
							sendInternalErrorResponse(stream)
						}
						llmTokensConsumed = tokens
					}
				}
				log.Infof("LLM Tokens Consumed: %d", llmTokensConsumed) // Example usage
				llmQuotaArgs = quota.Args{QuotaAmount: llmTokensConsumed}
				result, err := s.handler.quotaMan.Apply(authContext, llmop, llmQuotaArgs)
				if err != nil {
					log.Errorf("Failed to apply quota: %v", err)
					sendInternalErrorResponse(stream)
				}
				if result.Exceeded > 0 {
					sendResourceExceededResponse(stream)
				} else {
					sendContinueHeadersResponse(stream)
				}
			}
			sendContinueHeadersResponse(stream)

		case *extproc.ProcessingRequest_ResponseBody:
			if llmQuotaUsageLocation == "payload" {
				if quotaAttrs.LlmTokenUsagePayloadJsonPath == "" {
					//Return an exception
					log.Errorf("LLM Token Quota Usage Location is set to payload but no JSON Path is provided 'llm-token-usage-payload-json-path' is set to %+v . Please set 'llm-token-usage-payload-json-path' variable", quotaAttrs.LlmTokenUsagePayloadJsonPath)
					sendInternalErrorResponse(stream)
				}
				fmt.Println("Processing RESPONSE body")
				var jsonBody interface{}
				err := json.Unmarshal([]byte(request.ResponseBody.GetBody()), &jsonBody)
				if err != nil {
					log.Errorf("Failed to unmarshal response body: %v", err)
				}
				log.Infof("Response Body (JSON): %+v", jsonBody)
				res, err := jsonpath.JsonPathLookup(jsonBody, quotaAttrs.LlmTokenUsagePayloadJsonPath)
				if err != nil {
					log.Errorf("Error extracting data from JSON payload using path %s: %v", quotaAttrs.LlmTokenUsagePayloadJsonPath, err)
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
				log.Infof("LLM Tokens Consumed: %d", llmTokensConsumed) // Example usage
				llmQuotaArgs = quota.Args{QuotaAmount: llmTokensConsumed}
				result, err := s.handler.quotaMan.Apply(authContext, llmop, llmQuotaArgs)
				if err != nil {
					log.Errorf("Failed to apply quota: %v", err)
					sendInternalErrorResponse(stream)
				}
				if result.Exceeded > 0 {
					sendResourceExceededResponse(stream)
				} else {
					sendContinueBodyResponse(stream)
				}
			}
			sendContinueBodyResponse(stream)
		default:
			sendContinueBodyResponse(stream)
		}

	}
}

func sendContinueHeadersResponse(stream extproc.ExternalProcessor_ProcessServer) error {
	resp := &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extproc.HeadersResponse{
				Response: &extproc.CommonResponse{
					Status: extproc.CommonResponse_CONTINUE,
				},
			},
		},
	}
	if err := stream.Send(resp); err != nil {
		return err
	}
	return nil
}
func sendContinueBodyResponse(stream extproc.ExternalProcessor_ProcessServer) error {
	resp := &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_ResponseBody{
			ResponseBody: &extproc.BodyResponse{
				Response: &extproc.CommonResponse{
					Status: extproc.CommonResponse_CONTINUE,
				},
			},
		},
	}
	if err := stream.Send(resp); err != nil {
		return err
	}
	return nil
}
func sendResourceExceededResponse(stream extproc.ExternalProcessor_ProcessServer) error {
	resp := &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extproc.ImmediateResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_TooManyRequests,
				},
				Body: []byte("Rate limit exceeded"),
			},
		},
	}

	if err := stream.Send(resp); err != nil {
		return err
	}
	return nil
}

func sendInternalErrorResponse(stream extproc.ExternalProcessor_ProcessServer) error {
	resp := &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extproc.ImmediateResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_InternalServerError,
				},
				Body: []byte("Internal Server Error"),
			},
		},
	}

	if err := stream.Send(resp); err != nil {
		return err
	}
	return nil
}
