/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.pinot.server.api.resources;

import javax.inject.Inject;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import org.apache.pinot.server.starter.ServerInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * REST API to change server query scheduler. This is intended for testing ONLY.
 * The goal is easily change server query scheduler without the need to redploy configs or
 * restart server for comparison of different scheduling strategies.
 */
@Path("/")
public class SchedulerResource {
  private static Logger LOGGER = LoggerFactory.getLogger(SchedulerResource.class);

  @Inject
  ServerInstance server;

  // Missing swagger doc is intentional
  @POST
  @Path("scheduler")
  public void setQueryScheduler(String schedulerName) {
    server.resetQueryScheduler(schedulerName);
  }
}

