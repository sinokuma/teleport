/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package services

import (
	"fmt"
	"testing"
	"time"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"

	"gopkg.in/check.v1"
)

type ServerSuite struct {
}

var _ = check.Suite(&ServerSuite{})
var _ = testing.Verbose
var _ = fmt.Printf

func (s *ServerSuite) SetUpSuite(c *check.C) {
	utils.InitLoggerForTests(testing.Verbose())
}

// TestServersCompare tests comparing two servers
func (s *ServerSuite) TestServersCompare(c *check.C) {
	node := &ServerV2{
		Kind:    KindNode,
		Version: V2,
		Metadata: Metadata{
			Name:      "node1",
			Namespace: defaults.Namespace,
			Labels:    map[string]string{"a": "b"},
		},
		Spec: ServerSpecV2{
			Addr:      "localhost:3022",
			CmdLabels: map[string]CommandLabelV2{"a": CommandLabelV2{Period: Duration(time.Minute), Command: []string{"ls", "-l"}}},
			Version:   "4.0.0",
		},
	}
	node.SetExpiry(time.Date(2018, 1, 2, 3, 4, 5, 6, time.UTC))
	// Server is equal to itself
	c.Assert(CompareServers(node, node), check.Equals, Equal)

	// Only timestamps are different
	node2 := *node
	node2.SetExpiry(time.Date(2018, 1, 2, 3, 4, 5, 8, time.UTC))
	c.Assert(CompareServers(node, &node2), check.Equals, OnlyTimestampsDifferent)

	// Labels are different
	node2 = *node
	node2.Metadata.Labels = map[string]string{"a": "d"}
	c.Assert(CompareServers(node, &node2), check.Equals, Different)

	// Command labels are different
	node2 = *node
	node2.Spec.CmdLabels = map[string]CommandLabelV2{"a": CommandLabelV2{Period: Duration(time.Minute), Command: []string{"ls", "-lR"}}}
	c.Assert(CompareServers(node, &node2), check.Equals, Different)

	// Address has changed
	node2 = *node
	node2.Spec.Addr = "localhost:3033"
	c.Assert(CompareServers(node, &node2), check.Equals, Different)

	// Public addr has changed
	node2 = *node
	node2.Spec.PublicAddr = "localhost:3033"
	c.Assert(CompareServers(node, &node2), check.Equals, Different)

	// Hostname has changed
	node2 = *node
	node2.Spec.Hostname = "luna2"
	c.Assert(CompareServers(node, &node2), check.Equals, Different)

	// TeleportVersion has changed
	node2 = *node
	node2.Spec.Version = "5.0.0"
	c.Assert(CompareServers(node, &node2), check.Equals, Different)

	// Rotation has changed
	node2 = *node
	node2.Spec.Rotation = Rotation{
		State:       RotationStateInProgress,
		Phase:       RotationPhaseUpdateClients,
		CurrentID:   "1",
		Started:     time.Date(2018, 3, 4, 5, 6, 7, 8, time.UTC),
		GracePeriod: Duration(3 * time.Hour),
		LastRotated: time.Date(2017, 2, 3, 4, 5, 6, 7, time.UTC),
		Schedule: RotationSchedule{
			UpdateClients: time.Date(2018, 3, 4, 5, 6, 7, 8, time.UTC),
			UpdateServers: time.Date(2018, 3, 4, 7, 6, 7, 8, time.UTC),
			Standby:       time.Date(2018, 3, 4, 5, 6, 13, 8, time.UTC),
		},
	}
	c.Assert(CompareServers(node, &node2), check.Equals, Different)
}

// TestGuessProxyHostAndVersion checks that the GuessProxyHostAndVersion
// correctly guesses the public address of the proxy (Teleport Cluster).
func (s *ServerSuite) TestGuessProxyHostAndVersion(c *check.C) {
	// No proxies passed in.
	host, version, err := GuessProxyHostAndVersion(nil)
	c.Assert(host, check.Equals, "")
	c.Assert(version, check.Equals, "")
	c.Assert(err, check.FitsTypeOf, trace.NotFound(""))

	// No proxies have public address set.
	proxyA := ServerV2{}
	proxyA.Spec.Hostname = "test-A"
	proxyA.Spec.Version = "test-A"

	host, version, err = GuessProxyHostAndVersion([]Server{&proxyA})
	c.Assert(host, check.Equals, fmt.Sprintf("%v:%v", proxyA.Spec.Hostname, defaults.HTTPListenPort))
	c.Assert(version, check.Equals, proxyA.Spec.Version)
	c.Assert(err, check.IsNil)

	// At least one proxy has public address set.
	proxyB := ServerV2{}
	proxyB.Spec.PublicAddr = "test-B"
	proxyB.Spec.Version = "test-B"

	host, version, err = GuessProxyHostAndVersion([]Server{&proxyA, &proxyB})
	c.Assert(host, check.Equals, proxyB.Spec.PublicAddr)
	c.Assert(version, check.Equals, proxyB.Spec.Version)
	c.Assert(err, check.IsNil)
}
