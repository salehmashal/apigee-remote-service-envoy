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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

func makeMetadataHeaders(api string, ac *auth.Context, authorized bool, llmTokenQuotaAttributes *LLMTokenQuotaAttributes) []*core.HeaderValueOption {
	if ac == nil {
		return nil
	}

	headers := []*core.HeaderValueOption{
		header(headerAccessToken, ac.AccessToken),
		header(headerAPI, api),
		header(headerAPIProducts, strings.Join(ac.APIProducts, ",")),
		header(headerApplication, ac.Application),
		header(headerClientID, ac.ClientID),
		header(headerDeveloperEmail, ac.DeveloperEmail),
		header(headerEnvironment, ac.Environment()),
		header(headerOrganization, ac.Organization()),
		header(headerScope, strings.Join(ac.Scopes, " ")),
		header(headerAnalyticsProduct, ac.AnalyticsProduct),
	}
	// Serialize the req parameter and add it to the fields map
	if llmTokenQuotaAttributes != nil {
		reqJSON, err := json.Marshal(llmTokenQuotaAttributes)
		if err != nil {
			// Handle the error, e.g., log it or return an error
			fmt.Printf("Failed to marshal CheckRequest: %v", err)
		} else {
			headers = append(headers, header(headerLLMQuotaAttributes, string(reqJSON)))
		}
	}

	if ac.CustomAttributes != "" {
		headers = append(headers, header(headerCustomAttributes, ac.CustomAttributes))
	}
	if authorized {
		headers = append(headers, header(headerAuthorized, "true"))
	}

	return headers
}

func header(key, value string) *core.HeaderValueOption {
	return &core.HeaderValueOption{
		Header: &core.HeaderValue{
			Key:   key,
			Value: value,
		},
	}
}

func (h *Handler) decodeMetadataHeaders(headers map[string]string) (string, *auth.Context) {

	api, ok := headers[headerAPI]
	if !ok {
		if api, ok = headers[h.apiHeader]; ok {
			log.Debugf("No context header %s, using api header: %s", headerAPI, h.apiHeader)
		} else {
			log.Debugf("No context header %s or api header: %s", headerAPI, h.apiHeader)
			return "", nil
		}
	}

	var rootContext context.Context = h
	if h.isMultitenant {
		if headers[headerEnvironment] == "" {
			log.Warnf("Multitenant mode but %s header not found. Check Envoy config.", headerEnvironment)
		}
		rootContext = &multitenantContext{h, headers[headerEnvironment]}
	}

	return api, &auth.Context{
		Context:          rootContext,
		AccessToken:      headers[headerAccessToken],
		APIProducts:      strings.Split(headers[headerAPIProducts], ","),
		Application:      headers[headerApplication],
		ClientID:         headers[headerClientID],
		DeveloperEmail:   headers[headerDeveloperEmail],
		Scopes:           strings.Split(headers[headerScope], " "),
		CustomAttributes: headers[headerCustomAttributes],
		AnalyticsProduct: headers[headerAnalyticsProduct],
	}
}
