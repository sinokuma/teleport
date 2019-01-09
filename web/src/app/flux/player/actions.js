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

import history from 'app/services/history';
import cfg from 'app/config';
import { getAcl } from './../userAcl/store';

export function open(siteId, sid) {
  const routeUrl = cfg.getPlayerUrl({siteId, sid});
  history.push(routeUrl);
}

export function close(clusterId) {
  const canListSessions = getAcl().getSessionAccess().read;
  const clusterSessionUrl = cfg.getClusterSessionsUrl(clusterId)
  const redirect = canListSessions ? clusterSessionUrl : cfg.routes.app;

  history.push(redirect);
}
