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
	"fmt"
	"io"

	"github.com/elastic/beats/v7/metricbeat/helper"
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/beats/v7/metricbeat/mb/parse"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

const (
	defaultScheme = "http"
	defaultport   = "9090"
)

var (
	hostParser = parse.URLHostParserBuilder{
		DefaultScheme: defaultScheme,
		DefaultPort:   defaultport,
	}.Build()
)

func init() {
	mb.Registry.MustAddMetricSet("prometheus", "query", New,
		mb.WithHostParser(hostParser),
	)
}

// MetricSet type defines all fields of the MetricSet for Prometheus Query
type MetricSet struct {
	mb.BaseMetricSet
	http    *helper.HTTP
	queries []QueryConfig
	baseURL string
}

// New create a new instance of the MetricSet
// Part of new is also setting up the configuration by processing additional
// configuration entries if needed.
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {
	config := defaultConfig()
	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, err
	}

	http, err := helper.NewHTTP(base)
	if err != nil {
		return nil, err
	}
	return &MetricSet{
		BaseMetricSet: base,
		http:          http,
		queries:       config.Queries,
		baseURL:       http.GetURI(),
	}, nil
}

// Fetch methods implements the data gathering and data conversion to the right
// format. It publishes the event which is then forwarded to the output. In case
// of an error set the Error field of mb.Event or simply call report.Error().
func (m *MetricSet) Fetch(reporter mb.ReporterV2) error {
	for _, pathConfig := range m.queries {
		url := m.getURL(pathConfig.Path, pathConfig.Params)
		m.http.SetURI(url)
		response, err := m.http.FetchResponse()
		if err != nil {
			reporter.Error(fmt.Errorf("unable to fetch data from prometheus endpoint %v: %w", url, err))
			continue
		}
		defer func() {
			if err := response.Body.Close(); err != nil {
				m.Logger().Debug("error closing http body")
			}
		}()

		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}

		if response.StatusCode > 399 {
			m.Logger().Debugf("error received from prometheus endpoint %v: %v", url, string(body))
			reporter.Error(fmt.Errorf("unexpected status code %d from %v", response.StatusCode, url))
			continue
		}

		events, parseErr := parseResponse(body, pathConfig)
		if parseErr != nil {
			reporter.Error(fmt.Errorf("error parsing response from %v: %w", url, parseErr))
			continue
		}
		for _, e := range events {
			reporter.Event(e)
		}
	}
	return nil
}

func (m *MetricSet) getURL(path string, queryMap mapstr.M) string {
	queryStr := mb.QueryParams(queryMap).String()
	return m.baseURL + path + "?" + queryStr
}
