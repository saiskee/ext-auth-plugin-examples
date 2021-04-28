package pkg

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/solo-io/ext-auth-plugins/api"
	"github.com/solo-io/go-utils/contextutils"
	"go.uber.org/zap"
)

var (
	UnexpectedConfigError = func(typ interface{}) error {
		return errors.New(fmt.Sprintf("unexpected config type %T", typ))
	}
	_ api.ExtAuthPlugin = new(RequiredHeaderPlugin)
)

type RequiredHeaderPlugin struct{}

type Config struct {
}

func (p *RequiredHeaderPlugin) NewConfigInstance(ctx context.Context) (interface{}, error) {
	return &Config{}, nil
}

func (p *RequiredHeaderPlugin) GetAuthService(ctx context.Context, configInstance interface{}) (api.AuthService, error) {
	_, ok := configInstance.(*Config)
	if !ok {
		return nil, UnexpectedConfigError(configInstance)
	}

	_ = session.Must(session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"),
	}))
	return &RequiredHeaderAuthService{}, nil
}

type RequiredHeaderAuthService struct {
	RequiredHeader string
	AllowedValues  map[string]bool
}

// You can use the provided context to perform operations that are bound to the services lifecycle.
func (c *RequiredHeaderAuthService) Start(context.Context) error {
	// no-op
	return nil
}

func (c *RequiredHeaderAuthService) Authorize(ctx context.Context, request *api.AuthorizationRequest) (*api.AuthorizationResponse, error) {
	for key, value := range request.CheckRequest.GetAttributes().GetRequest().GetHttp().GetHeaders() {
		if key == c.RequiredHeader {
			logger(ctx).Infow("Found required header, checking value.", "header", key, "value", value)

			if _, ok := c.AllowedValues[value]; ok {
				logger(ctx).Infow("Header value match. Allowing request.")
				response := api.AuthorizedResponse()

				// Append extra header
				response.CheckResponse.HttpResponse = &envoy_service_auth_v3.CheckResponse_OkResponse{
					OkResponse: &envoy_service_auth_v3.OkHttpResponse{
						Headers: []*envoy_config_core_v3.HeaderValueOption{{
							Header: &envoy_config_core_v3.HeaderValue{
								Key:   "matched-allowed-headers",
								Value: "true",
							},
						}},
					},
				}
				return response, nil
			}
			logger(ctx).Infow("Header value does not match allowed values, denying access.")
			return api.UnauthorizedResponse(), nil
		}
	}
	logger(ctx).Infow("Required header not found, denying access")
	return api.UnauthorizedResponse(), nil
}

func logger(ctx context.Context) *zap.SugaredLogger {
	return contextutils.LoggerFrom(contextutils.WithLogger(ctx, "header_value_plugin"))
}
