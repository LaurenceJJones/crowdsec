package ctiexpr

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

const validApiKey = "my-api-key"

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

var sampledata = map[string]cticlient.SmokeItem{
	// 1.2.3.4 is a known false positive
	"1.2.3.4": {
		Ip: "1.2.3.4",
		Classifications: cticlient.CTIClassifications{
			FalsePositives: []cticlient.CTIClassification{
				{
					Name:  "example_false_positive",
					Label: "Example False Positive",
				},
			},
		},
	},
	// 1.2.3.5 is a known bad-guy, and part of FIRE
	"1.2.3.5": {
		Ip: "1.2.3.5",
		Classifications: cticlient.CTIClassifications{
			Classifications: []cticlient.CTIClassification{
				{
					Name:        "community-blocklist",
					Label:       "CrowdSec Community Blocklist",
					Description: "IP belong to the CrowdSec Community Blocklist",
				},
			},
		},
	},
	// 1.2.3.6 is a bad guy (high bg noise), but not in FIRE
	"1.2.3.6": {
		Ip:                   "1.2.3.6",
		BackgroundNoiseScore: new(int),
		Behaviors: []*cticlient.CTIBehavior{
			{Name: "ssh:bruteforce", Label: "SSH Bruteforce", Description: "SSH Bruteforce"},
		},
		AttackDetails: []*cticlient.CTIAttackDetails{
			{Name: "crowdsecurity/ssh-bf", Label: "Example Attack"},
			{Name: "crowdsecurity/ssh-slow-bf", Label: "Example Attack"},
		},
	},
	// 1.2.3.7 is a ok guy, but part of a bad range
	"1.2.3.7": {},
}

func smokeHandler(req *http.Request) *http.Response {
	apiKey := req.Header.Get("X-Api-Key")
	if apiKey != validApiKey {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       nil,
			Header:     make(http.Header),
		}
	}

	requestedIP := strings.Split(req.URL.Path, "/")[3]

	sample, ok := sampledata[requestedIP]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       nil,
			Header:     make(http.Header),
		}
	}

	body, err := json.Marshal(sample)
	if err != nil {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       nil,
			Header:     make(http.Header),
		}
	}

	reader := io.NopCloser(bytes.NewReader(body))

	return &http.Response{
		StatusCode: http.StatusOK,
		// Send response to be tested
		Body:          reader,
		Header:        make(http.Header),
		ContentLength: 0,
	}
}

func TestNilClient(t *testing.T) {
	defer ShutdownCrowdsecCTI()

	if err := InitCrowdsecCTI(ptr.Of(""), nil, nil, nil); !errors.Is(err, cticlient.ErrDisabled) {
		t.Fatalf("failed to init CTI : %s", err)
	}

	item, err := CrowdsecCTI("1.2.3.4")
	assert.Equal(t, err, cticlient.ErrDisabled)
	assert.Equal(t, &cticlient.SmokeItem{}, item)
}

func TestInvalidAuth(t *testing.T) {
	defer ShutdownCrowdsecCTI()

	if err := InitCrowdsecCTI(ptr.Of("asdasd"), nil, nil, nil); err != nil {
		t.Fatalf("failed to init CTI : %s", err)
	}
	// Replace the client created by InitCrowdsecCTI with one that uses a custom transport
	ctiClient = cticlient.NewCrowdsecCTIClient(cticlient.WithAPIKey("asdasd"), cticlient.WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(smokeHandler),
	}))

	item, err := CrowdsecCTI("1.2.3.4")
	assert.Equal(t, &cticlient.SmokeItem{}, item)
	assert.False(t, CTIApiEnabled)
	assert.Equal(t, err, cticlient.ErrUnauthorized)

	// CTI is now disabled, all requests should return empty
	ctiClient = cticlient.NewCrowdsecCTIClient(cticlient.WithAPIKey(validApiKey), cticlient.WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(smokeHandler),
	}))

	item, err = CrowdsecCTI("1.2.3.4")
	assert.Equal(t, &cticlient.SmokeItem{}, item)
	assert.False(t, CTIApiEnabled)
	assert.Equal(t, err, cticlient.ErrDisabled)
}

func TestNoKey(t *testing.T) {
	defer ShutdownCrowdsecCTI()

	err := InitCrowdsecCTI(nil, nil, nil, nil)
	require.ErrorIs(t, err, cticlient.ErrDisabled)
	// Replace the client created by InitCrowdsecCTI with one that uses a custom transport
	ctiClient = cticlient.NewCrowdsecCTIClient(cticlient.WithAPIKey("asdasd"), cticlient.WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(smokeHandler),
	}))

	item, err := CrowdsecCTI("1.2.3.4")
	assert.Equal(t, &cticlient.SmokeItem{}, item)
	assert.False(t, CTIApiEnabled)
	assert.Equal(t, err, cticlient.ErrDisabled)
}

func TestCache(t *testing.T) {
	defer ShutdownCrowdsecCTI()

	cacheDuration := 1 * time.Second
	if err := InitCrowdsecCTI(ptr.Of(validApiKey), &cacheDuration, nil, nil); err != nil {
		t.Fatalf("failed to init CTI : %s", err)
	}
	// Replace the client created by InitCrowdsecCTI with one that uses a custom transport
	ctiClient = cticlient.NewCrowdsecCTIClient(cticlient.WithAPIKey(validApiKey), cticlient.WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(smokeHandler),
	}))

	item, err := CrowdsecCTI("1.2.3.4")
	ctiResp := item.(*cticlient.SmokeItem)
	assert.Equal(t, "1.2.3.4", ctiResp.Ip)
	assert.True(t, CTIApiEnabled)
	assert.Equal(t, 1, CTICache.Len(true))
	require.NoError(t, err)

	item, err = CrowdsecCTI("1.2.3.4")
	ctiResp = item.(*cticlient.SmokeItem)

	assert.Equal(t, "1.2.3.4", ctiResp.Ip)
	assert.True(t, CTIApiEnabled)
	assert.Equal(t, 1, CTICache.Len(true))
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	assert.Equal(t, 0, CTICache.Len(true))

	item, err = CrowdsecCTI("1.2.3.4")
	ctiResp = item.(*cticlient.SmokeItem)

	assert.Equal(t, "1.2.3.4", ctiResp.Ip)
	assert.True(t, CTIApiEnabled)
	assert.Equal(t, 1, CTICache.Len(true))
	require.NoError(t, err)
}
