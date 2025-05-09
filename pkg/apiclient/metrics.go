package apiclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type MetricsService service

func (s *MetricsService) Add(ctx context.Context, metrics *models.Metrics) (interface{}, *Response, error) {
	u := fmt.Sprintf("%s/metrics/", s.client.URLPrefix)

	req, err := s.client.PrepareRequest(ctx, http.MethodPost, u, &metrics)
	if err != nil {
		return nil, nil, err
	}

	var response interface{}

	resp, err := s.client.Do(ctx, req, &response)
	if err != nil {
		return nil, resp, err
	}

	return &response, resp, nil
}
