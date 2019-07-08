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
package org.apache.pinot.broker.broker;

import com.google.common.base.Preconditions;
import com.yammer.metrics.core.MetricsRegistry;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.commons.configuration.Configuration;
import org.apache.pinot.broker.queryquota.QueryQuotaManager;
import org.apache.pinot.broker.requesthandler.BrokerRequestHandler;
import org.apache.pinot.broker.requesthandler.ConnectionPoolBrokerRequestHandler;
import org.apache.pinot.broker.requesthandler.SingleConnectionBrokerRequestHandler;
import org.apache.pinot.broker.routing.RoutingTable;
import org.apache.pinot.broker.routing.TimeBoundaryService;
import org.apache.pinot.common.metrics.BrokerMetrics;
import org.apache.pinot.common.metrics.MetricsHelper;
import org.apache.pinot.common.utils.CommonConstants.Broker;
import org.apache.pinot.common.utils.CommonConstants.Helix;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;


public class BrokerServerBuilder {
  private static final Logger LOGGER = LoggerFactory.getLogger(BrokerServerBuilder.class);
  private static final String USE_SSL = "pinot.broker.ssl.enabled";
  private static final String KEYSTORE_FILE = "pinot.broker.ssl.keystore.file";
  private static final String KEYSTORE_PASSWORD = "pinot.broker.ssl.keystore.pass";
  private static final String TRUSTSTORE_FILE = "pinot.broker.ssl.truststore.file";
  private static final String TRUSTSTORE_PASSWORD = "pinot.broker.ssl.truststore.pass";

  public enum State {
    INIT, STARTING, RUNNING, SHUTTING_DOWN, SHUTDOWN
  }

  // Running State Of broker
  private final AtomicReference<State> _state = new AtomicReference<>(State.INIT);

  private final Configuration _config;
  private final long _delayedShutdownTimeMs;
  private final RoutingTable _routingTable;
  private final TimeBoundaryService _timeBoundaryService;
  private final QueryQuotaManager _queryQuotaManager;
  private final AccessControlFactory _accessControlFactory;
  private final MetricsRegistry _metricsRegistry;
  private final BrokerMetrics _brokerMetrics;
  private final BrokerRequestHandler _brokerRequestHandler;
  private final BrokerAdminApiApplication _brokerAdminApplication;

  public BrokerServerBuilder(Configuration config, RoutingTable routingTable, TimeBoundaryService timeBoundaryService,
      QueryQuotaManager queryQuotaManager) {
    _config = config;
    _delayedShutdownTimeMs =
        config.getLong(Broker.CONFIG_OF_DELAY_SHUTDOWN_TIME_MS, Broker.DEFAULT_DELAY_SHUTDOWN_TIME_MS);
    _routingTable = routingTable;
    _timeBoundaryService = timeBoundaryService;
    _queryQuotaManager = queryQuotaManager;
    _accessControlFactory = AccessControlFactory.loadFactory(_config.subset(Broker.ACCESS_CONTROL_CONFIG_PREFIX));
    _metricsRegistry = new MetricsRegistry();
    MetricsHelper.initializeMetrics(config.subset(Broker.METRICS_CONFIG_PREFIX));
    MetricsHelper.registerMetricsRegistry(_metricsRegistry);
    _brokerMetrics =
        new BrokerMetrics(_metricsRegistry, !_config.getBoolean(Broker.CONFIG_OF_ENABLE_TABLE_LEVEL_METRICS, true));
    _brokerMetrics.initializeGlobalMeters();
    _brokerRequestHandler = buildRequestHandler();
    _brokerAdminApplication = new BrokerAdminApiApplication(this);
  }

  private BrokerRequestHandler buildRequestHandler() {
    String requestHandlerType =
        _config.getString(Broker.CONFIG_OF_REQUEST_HANDLER_TYPE, Broker.DEFAULT_REQUEST_HANDLER_TYPE);
    if (requestHandlerType.equalsIgnoreCase(Broker.CONNECTION_POOL_REQUEST_HANDLER_TYPE)) {
      LOGGER.info("Using ConnectionPoolBrokerRequestHandler");
      return new ConnectionPoolBrokerRequestHandler(_config, _routingTable, _timeBoundaryService, _accessControlFactory,
          _queryQuotaManager, _brokerMetrics, _metricsRegistry);
    } else {
      LOGGER.info("Using SingleConnectionBrokerRequestHandler");
      return new SingleConnectionBrokerRequestHandler(_config, _routingTable, _timeBoundaryService,
          _accessControlFactory, _queryQuotaManager, _brokerMetrics);
    }
  }

  public void start() throws IOException{
    LOGGER.info("Starting Pinot Broker");

    Preconditions.checkState(_state.get() == State.INIT);
    _state.set(State.STARTING);

    _brokerRequestHandler.start();
    if (_config.containsKey(USE_SSL) && _config.getBoolean(USE_SSL))
    {
      if(!(_config.containsKey(KEYSTORE_FILE) && _config.containsKey(KEYSTORE_PASSWORD)
          && _config.containsKey(TRUSTSTORE_FILE) && _config.containsKey(TRUSTSTORE_PASSWORD)) ){
        throw new IOException("Have not specified all required SSL configs: key/truststore file paths and passwords");
      }
      else {
        _brokerAdminApplication.setSSLConfigs(_config.getString(KEYSTORE_FILE), _config.getString(KEYSTORE_PASSWORD),
            _config.getString(TRUSTSTORE_FILE), _config.getString(TRUSTSTORE_PASSWORD));
      }
    }

    int brokerQueryPort = _config.getInt(Helix.KEY_OF_BROKER_QUERY_PORT, Helix.DEFAULT_BROKER_QUERY_PORT);
    _brokerAdminApplication.start(brokerQueryPort);

    _state.set(State.RUNNING);
    LOGGER.info("Pinot Broker is started and listening on port {} for API requests", brokerQueryPort);
  }

  public void stop() {
    LOGGER.info("Shutting down Pinot Broker");

    try {
      Thread.sleep(_delayedShutdownTimeMs);
    } catch (Exception e) {
      LOGGER.error("Caught exception while waiting for shutdown delay period of {}ms", _delayedShutdownTimeMs, e);
    }

    Preconditions.checkState(_state.get() == State.RUNNING);
    _state.set(State.SHUTTING_DOWN);

    _brokerRequestHandler.shutDown();
    _brokerAdminApplication.stop();

    _state.set(State.SHUTDOWN);
    LOGGER.info("Finish shutting down Pinot Broker");
  }

  public State getCurrentState() {
    return _state.get();
  }

  public RoutingTable getRoutingTable() {
    return _routingTable;
  }

  public TimeBoundaryService getTimeBoundaryService() {
    return _timeBoundaryService;
  }

  public AccessControlFactory getAccessControlFactory() {
    return _accessControlFactory;
  }

  public MetricsRegistry getMetricsRegistry() {
    return _metricsRegistry;
  }

  public BrokerMetrics getBrokerMetrics() {
    return _brokerMetrics;
  }

  public BrokerRequestHandler getBrokerRequestHandler() {
    return _brokerRequestHandler;
  }
}
