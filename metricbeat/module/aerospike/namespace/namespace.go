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

package namespace

import (
	"fmt"
	"strings"

	as "github.com/aerospike/aerospike-client-go/v7"

	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/beats/v7/metricbeat/module/aerospike"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

// init registers the MetricSet with the central registry.
// The New method will be called after the setup of the module and before starting to fetch data
func init() {
	mb.Registry.MustAddMetricSet("aerospike", "namespace", New,
		mb.DefaultMetricSet(),
	)
}

// MetricSet type defines all fields of the MetricSet
// As a minimum it must inherit the mb.BaseMetricSet fields, but can be extended with
// additional entries. These variables can be used to persist data or configuration between
// multiple fetch calls.
type MetricSet struct {
	mb.BaseMetricSet
	host         *as.Host
	clientPolicy *as.ClientPolicy
	client       *as.Client
	infoPolicy   *as.InfoPolicy
}

// New create a new instance of the MetricSet
// Part of new is also setting up the configuration by processing additional
// configuration entries if needed.
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {
	config := aerospike.DefaultConfig()
	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, err
	}

	host, err := aerospike.ParseHost(base.Host())
	if err != nil {
		return nil, fmt.Errorf("Invalid host format, expected hostname:port: %w", err)
	}

	clientPolicy, err := aerospike.ParseClientPolicy(config)
	if err != nil {
		return nil, fmt.Errorf("could not initialize aerospike client policy: %w", err)
	}

	return &MetricSet{
		BaseMetricSet: base,
		host:          host,
		clientPolicy:  clientPolicy,
		infoPolicy:    as.NewInfoPolicy(),
	}, nil
}

// Fetch methods implements the data gathering and data conversion to the right
// format. It publishes the event which is then forwarded to the output. In case
// of an error set the Error field of mb.Event or simply call report.Error().
func (m *MetricSet) Fetch(reporter mb.ReporterV2) error {
	if err := m.connect(); err != nil {
		return fmt.Errorf("error connecting to Aerospike: %w", err)
	}

	for _, node := range m.client.GetNodes() {
		info, err := node.RequestInfo(m.infoPolicy, "namespaces")
		if err != nil {
			m.Logger().Errorf("Failed to retrieve namespaces from node %s", node.GetName())
			continue
		}

		for _, namespace := range strings.Split(info["namespaces"], ";") {
			info, err := node.RequestInfo(m.infoPolicy, "namespace/"+namespace)
			if err != nil {
				m.Logger().Errorf("Failed to retrieve metrics for namespace %s from node %s", namespace, node.GetName())
				continue
			}

			data, _ := schema.Apply(aerospike.ParseInfo(info["namespace/"+namespace]))
			data["name"] = namespace
			data["node"] = mapstr.M{
				"host": node.GetHost().String(),
				"name": node.GetName(),
			}

			reporter.Event(mb.Event{MetricSetFields: data})
		}
	}

	return nil
}

// create an aerospike client if it doesn't exist yet
func (m *MetricSet) connect() error {
	if m.client == nil {
		client, err := as.NewClientWithPolicyAndHost(m.clientPolicy, m.host)
		if err != nil {
			return err
		}
		m.client = client
	}
	return nil
}
