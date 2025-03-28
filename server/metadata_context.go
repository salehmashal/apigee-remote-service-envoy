// Copyright 2021 Google LLC
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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	extAuthzFilterNamespace = "envoy.filters.http.ext_authz"

	headerAuthorized         = "x-apigee-authorized"
	headerAccessToken        = "x-apigee-accesstoken"
	headerAPI                = "x-apigee-api"
	headerAPIProducts        = "x-apigee-apiproducts"
	headerApplication        = "x-apigee-application"
	headerClientID           = "x-apigee-clientid"
	headerDeveloperEmail     = "x-apigee-developeremail"
	headerEnvironment        = "x-apigee-environment"
	headerOrganization       = "x-apigee-organization"
	headerScope              = "x-apigee-scope"
	headerCustomAttributes   = "x-apigee-customattributes"
	headerAnalyticsProduct   = "x-apigee-analytics-product"
	headerLLMQuotaAttributes = "x-apigee-llm-quota-attributes"
)

// encodeExtAuthzMetadata encodes given api and auth context into
// Envoy ext_authz's filter's dynamic metadata
func encodeExtAuthzMetadata(api string, ac *auth.Context, authorized bool, llmTokenQuotaAttributes *LLMTokenQuotaAttributes) *structpb.Struct {
	if ac == nil {
		return nil
	}

	fields := map[string]*structpb.Value{
		headerAccessToken:      stringValueFrom(ac.AccessToken),
		headerAPI:              stringValueFrom(api),
		headerAPIProducts:      stringValueFrom(strings.Join(ac.APIProducts, ",")),
		headerApplication:      stringValueFrom(ac.Application),
		headerClientID:         stringValueFrom(ac.ClientID),
		headerDeveloperEmail:   stringValueFrom(ac.DeveloperEmail),
		headerEnvironment:      stringValueFrom(ac.Environment()),
		headerOrganization:     stringValueFrom(ac.Organization()),
		headerScope:            stringValueFrom(strings.Join(ac.Scopes, " ")),
		headerAnalyticsProduct: stringValueFrom(ac.AnalyticsProduct),
	}

	if ac.CustomAttributes != "" {
		fields[headerCustomAttributes] = stringValueFrom(ac.CustomAttributes)
	}

	if authorized {
		fields[headerAuthorized] = stringValueFrom("true")
	}

	// Serialize the req parameter and add it to the fields map
	if llmTokenQuotaAttributes != nil {
		reqJSON, err := json.Marshal(llmTokenQuotaAttributes)
		reqContext, err := json.Marshal(ac)
		if err != nil {
			// Handle the error, e.g., log it or return an error
			fmt.Printf("Failed to marshal CheckRequest: %v", err)
		} else {
			fields[headerLLMQuotaAttributes] = stringValueFrom(string(reqJSON))
			fields["context"] = stringValueFrom(string(reqContext))
		}
	}

	return &structpb.Struct{
		Fields: fields,
	}
}

// stringValueFrom returns a *structpb.Value with a StringValue Kind
func stringValueFrom(v string) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_StringValue{
			StringValue: v,
		},
	}
}

func numberValueFrom(v float64) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_NumberValue{
			NumberValue: v,
		},
	}
}

func boolValueFrom(v bool) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_BoolValue{
			BoolValue: v,
		},
	}
}

func structValueFrom(v struct{}) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_StructValue{
			StructValue: &structpb.Struct{},
		},
	}
}

func structProtoValueFrom(v proto.Message) *structpb.Value {
	bytes, err := proto.Marshal(v)
	if err != nil {
		log.Errorf("Error marshaling proto message: %v", err)
		return &structpb.Value{} // Return empty struct on failure
	}
	var structVal structpb.Struct
	err = proto.Unmarshal(bytes, &structVal)
	if err != nil {
		log.Errorf("Error unmarshaling into Struct: %v", err)
		return &structpb.Value{}
	}
	return &structpb.Value{
		Kind: &structpb.Value_StructValue{StructValue: &structVal},
	}
}

// decodeExtAuthzMetadata decodes the Envoy ext_authz's filter's metadata
// fields into api and auth context
func (h *Handler) decodeExtAuthzMetadata(fields map[string]*structpb.Value) (string, *auth.Context) {

	api := fields[headerAPI].GetStringValue()
	if api == "" {
		log.Debugf("No context header: %s", headerAPI)
		return "", nil
	}

	var rootContext context.Context = h
	if h.isMultitenant {
		env := fields[headerEnvironment].GetStringValue()
		if env == "" {
			log.Warnf("Multitenant mode but %s header not found. Check Envoy config.", headerEnvironment)
		}
		rootContext = &multitenantContext{h, env}
	}

	return api, &auth.Context{
		Context:          rootContext,
		AccessToken:      fields[headerAccessToken].GetStringValue(),
		APIProducts:      strings.Split(fields[headerAPIProducts].GetStringValue(), ","),
		Application:      fields[headerApplication].GetStringValue(),
		ClientID:         fields[headerClientID].GetStringValue(),
		DeveloperEmail:   fields[headerDeveloperEmail].GetStringValue(),
		Scopes:           strings.Split(fields[headerScope].GetStringValue(), " "),
		CustomAttributes: fields[headerCustomAttributes].GetStringValue(),
		AnalyticsProduct: fields[headerAnalyticsProduct].GetStringValue(),
	}
}
