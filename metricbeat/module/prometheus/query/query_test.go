// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package query

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	mbtest "github.com/elastic/beats/v7/metricbeat/mb/testing"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

func TestQueryFetchEventContentInstantVector(t *testing.T) {
	absPath, _ := filepath.Abs("./_meta/test/")

	// test with response format like:
	//[
	//  {
	//    "metric": { "<label_name>": "<label_value>", ... },
	//    "value": [ <unix_time>, "<sample_value>" ]
	//  },
	//  ...
	//]
	response, _ := os.ReadFile(absPath + "/querymetrics_instant_vector.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json;")
		_, _ = w.Write(response)
	}))
	defer server.Close()

	config := map[string]interface{}{
		"module":     "prometheus",
		"metricsets": []string{"query"},
		"hosts":      []string{server.URL},
		// queries do not have an actual role here since all http responses are mocked
		"queries": []mapstr.M{
			mapstr.M{
				"name": "up",
				"path": "/api/v1/query",
				"params": mapstr.M{
					"query": "up",
				},
			},
		},
	}
	reporter := &mbtest.CapturingReporterV2{}

	metricSet := mbtest.NewReportingMetricSetV2Error(t, config)
	_ = metricSet.Fetch(reporter)

	events := reporter.GetEvents()
	if len(events) != 2 {
		t.Fatalf("Expected 2 events, had %d. %v\n", len(events), events)
	}
	for _, event := range events {
		e := mbtest.StandardizeEvent(metricSet, event)
		t.Logf("%s/%s event: %+v", metricSet.Module().Name(), metricSet.Name(), e.Fields.StringToPrint())
	}
}

func TestQueryFetchEventContentRangeVector(t *testing.T) {
	absPath, _ := filepath.Abs("./_meta/test/")

	// test with response format like:
	//[
	//  {
	//    "metric": { "<label_name>": "<label_value>", ... },
	//    "values": [ [ <unix_time>, "<sample_value>" ], ... ]
	//  },
	//  ...
	//]
	response, _ := os.ReadFile(absPath + "/querymetrics_range_vector.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json;")
		_, _ = w.Write(response)
	}))
	defer server.Close()

	config := map[string]interface{}{
		"module":     "prometheus",
		"metricsets": []string{"query"},
		"hosts":      []string{server.URL},
		// queries do not have an actual role here since all http responses are mocked
		"queries": []mapstr.M{
			mapstr.M{
				"name": "up_range",
				"path": "/api/v1/query",
				"params": mapstr.M{
					"query": "up",
					"start": "2019-12-20T23:30:30.000Z",
					"end":   "2019-12-21T23:31:00.000Z",
					"step":  "15s",
				},
			},
		},
	}
	reporter := &mbtest.CapturingReporterV2{}

	metricSet := mbtest.NewReportingMetricSetV2Error(t, config)
	_ = metricSet.Fetch(reporter)

	events := reporter.GetEvents()
	if len(events) != 6 {
		t.Fatalf("Expected 6 events, had %d. %v\n", len(events), events)
	}
	for _, event := range events {
		e := mbtest.StandardizeEvent(metricSet, event)
		t.Logf("%s/%s event: %+v", metricSet.Module().Name(), metricSet.Name(), e.Fields.StringToPrint())
	}
}

func TestQueryFetchEventContentScalar(t *testing.T) {
	absPath, _ := filepath.Abs("./_meta/test/")

	// test with response format like:
	//[ <unix_time>, "<scalar_value>" ]
	response, _ := os.ReadFile(absPath + "/querymetrics_scalar.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json;")
		_, _ = w.Write(response)
	}))
	defer server.Close()

	config := map[string]interface{}{
		"module":     "prometheus",
		"metricsets": []string{"query"},
		"hosts":      []string{server.URL},
		// queries do not have an actual role here since all http responses are mocked
		"queries": []mapstr.M{
			mapstr.M{
				"name": "scalar",
				"path": "/api/v1/query",
				"params": mapstr.M{
					"query": "100",
				},
			},
		},
	}
	reporter := &mbtest.CapturingReporterV2{}

	metricSet := mbtest.NewReportingMetricSetV2Error(t, config)
	_ = metricSet.Fetch(reporter)

	events := reporter.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 events, had %d. %v\n", len(events), events)
	}
	for _, event := range events {
		e := mbtest.StandardizeEvent(metricSet, event)
		t.Logf("%s/%s event: %+v", metricSet.Module().Name(), metricSet.Name(), e.Fields.StringToPrint())
	}
}

func TestQueryFetchEventContentString(t *testing.T) {
	absPath, _ := filepath.Abs("./_meta/test/")

	// test with response format like:
	//[ <unix_time>, "<scalar_value>" ]
	response, _ := os.ReadFile(absPath + "/querymetrics_string.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json;")
		_, _ = w.Write(response)
	}))
	defer server.Close()

	config := map[string]interface{}{
		"module":     "prometheus",
		"metricsets": []string{"query"},
		"hosts":      []string{server.URL},
		// queries do not have an actual role here since all http responses are mocked
		"queries": []mapstr.M{
			mapstr.M{
				"name": "string",
				"path": "/api/v1/query",
				"params": mapstr.M{
					"query": "some",
				},
			},
		},
	}
	reporter := &mbtest.CapturingReporterV2{}

	metricSet := mbtest.NewReportingMetricSetV2Error(t, config)
	_ = metricSet.Fetch(reporter)

	events := reporter.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 events, had %d. %v\n", len(events), events)
	}
	for _, event := range events {
		e := mbtest.StandardizeEvent(metricSet, event)
		t.Logf("%s/%s event: %+v", metricSet.Module().Name(), metricSet.Name(), e.Fields.StringToPrint())
	}
}

func TestHTTPErrorCodeHandling(t *testing.T) {
	statusCode := 400

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte("Client sent an HTTP request to an HTTPS server."))
	}))
	defer server.Close()

	config := map[string]interface{}{
		"module":     "prometheus",
		"metricsets": []string{"query"},
		"hosts":      []string{server.URL},
		// queries do not have an actual role here since all http responses are mocked
		"queries": []mapstr.M{
			mapstr.M{
				"name": "string",
				"path": "/api/v1/query",
				"params": mapstr.M{
					"query": "some",
				},
			},
		},
	}
	reporter := &mbtest.CapturingReporterV2{}

	metricSet := mbtest.NewReportingMetricSetV2Error(t, config)
	_ = metricSet.Fetch(reporter)

	errs := reporter.GetErrors()
	if len(errs) != 1 {
		t.Fatalf("Expected 1 error, had %d: %v\n", len(errs), errs)
	}

	if !strings.Contains(errs[0].Error(), strconv.Itoa(statusCode)) {
		t.Fatalf("Expected error to contain HTTP response code %d, got error: %s\n", statusCode, errs[0])
	}
}
