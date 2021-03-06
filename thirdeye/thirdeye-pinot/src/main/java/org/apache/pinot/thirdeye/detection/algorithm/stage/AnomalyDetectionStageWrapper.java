/*
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

package org.apache.pinot.thirdeye.detection.algorithm.stage;

import com.google.common.base.Preconditions;
import org.apache.pinot.thirdeye.anomaly.detection.DetectionJobSchedulerUtils;
import org.apache.pinot.thirdeye.common.time.TimeGranularity;
import org.apache.pinot.thirdeye.common.time.TimeSpec;
import org.apache.pinot.thirdeye.datalayer.dto.DatasetConfigDTO;
import org.apache.pinot.thirdeye.datalayer.dto.DetectionConfigDTO;
import org.apache.pinot.thirdeye.datalayer.dto.MergedAnomalyResultDTO;
import org.apache.pinot.thirdeye.datalayer.dto.MetricConfigDTO;
import org.apache.pinot.thirdeye.detection.ConfigUtils;
import org.apache.pinot.thirdeye.detection.DataProvider;
import org.apache.pinot.thirdeye.detection.DetectionPipeline;
import org.apache.pinot.thirdeye.detection.DetectionPipelineResult;
import org.apache.pinot.thirdeye.detection.DetectionUtils;
import org.apache.pinot.thirdeye.rootcause.impl.MetricEntity;
import org.apache.pinot.thirdeye.util.ThirdEyeUtils;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.commons.collections4.MapUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.Interval;
import org.joda.time.Period;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Anomaly Detection Stage Wrapper. This wrapper runs a anomaly detection stage and return the anomalies.
 * Optionally set the detection window to be moving window fashion. This wrapper will call detection multiple times with
 * sliding window. Each sliding window start time and end time is aligned to the data granularity. Each window size is set by the spec.
 */
public class AnomalyDetectionStageWrapper extends DetectionPipeline {
  private static final String PROP_STAGE_CLASSNAME = "stageClassName";
  private static final String PROP_SPECS = "specs";
  private static final String PROP_METRIC_URN = "metricUrn";

  // moving window detection properties
  private static final String PROP_MOVING_WINDOW_DETECTION = "isMovingWindowDetection";
  private static final String PROP_WINDOW_DELAY = "windowDelay";
  private static final String PROP_WINDOW_DELAY_UNIT = "windowDelayUnit";
  private static final String PROP_WINDOW_SIZE = "windowSize";
  private static final String PROP_WINDOW_UNIT = "windowUnit";
  private static final String PROP_FREQUENCY = "frequency";

  private static final Logger LOG = LoggerFactory.getLogger(AnomalyDetectionStageWrapper.class);

  private final String metricUrn;
  private final Map<String, Object> specs;
  private final String stageClassName;

  private final int windowDelay;
  private final TimeUnit windowDelayUnit;
  private final int windowSize;
  private final TimeUnit windowUnit;
  private final boolean isMovingWindowDetection;
  private DatasetConfigDTO dataset;
  private DateTimeZone dateTimeZone;
  // need to specify run frequency for minute level detection. Used for moving monitoring window alignment, default to be 15 minutes.
  private final TimeGranularity functionFrequency;

  public AnomalyDetectionStageWrapper(DataProvider provider, DetectionConfigDTO config, long startTime, long endTime) {
    super(provider, config, startTime, endTime);

    Map<String, Object> properties = config.getProperties();
    Preconditions.checkArgument(properties.containsKey(PROP_STAGE_CLASSNAME), "Missing " + PROP_STAGE_CLASSNAME);

    this.specs = ConfigUtils.getMap(properties.get(PROP_SPECS));
    this.stageClassName = MapUtils.getString(properties, PROP_STAGE_CLASSNAME);
    this.metricUrn = MapUtils.getString(config.getProperties(), PROP_METRIC_URN);
    if (this.metricUrn != null) {
      this.specs.put(PROP_METRIC_URN, metricUrn);
    }

    this.isMovingWindowDetection = MapUtils.getBooleanValue(this.specs, PROP_MOVING_WINDOW_DETECTION, false);
    // delays to wait for data becomes available
    this.windowDelay = MapUtils.getIntValue(this.specs, PROP_WINDOW_DELAY, 0);
    this.windowDelayUnit = TimeUnit.valueOf(MapUtils.getString(this.specs, PROP_WINDOW_DELAY_UNIT, "DAYS"));
    // detection window size
    this.windowSize = MapUtils.getIntValue(this.specs, PROP_WINDOW_SIZE, 1);
    this.windowUnit = TimeUnit.valueOf(MapUtils.getString(this.specs, PROP_WINDOW_UNIT, "DAYS"));
    Map<String, Object> frequency = ConfigUtils.getMap(this.specs.get(PROP_FREQUENCY), Collections.emptyMap());
    this.functionFrequency = new TimeGranularity(MapUtils.getIntValue(frequency, "size", 15), TimeUnit.valueOf(MapUtils.getString(frequency, "unit", "MINUTES")));
  }

  @Override
  public DetectionPipelineResult run() throws Exception {
    List<Interval> monitoringWindows = this.getMonitoringWindows();
    List<MergedAnomalyResultDTO> anomalies = new ArrayList<>();
    for (Interval window : monitoringWindows) {
      AnomalyDetectionStage anomalyDetectionStage = this.loadAnomalyDetectorStage(this.stageClassName);
      anomalyDetectionStage.init(specs, config.getId(), window.getStartMillis(), window.getEndMillis());
      anomalies.addAll(anomalyDetectionStage.runDetection(this.provider));
    }

    MetricEntity me = MetricEntity.fromURN(this.metricUrn);
    MetricConfigDTO metric = provider.fetchMetrics(Collections.singleton(me.getId())).get(me.getId());

    for (MergedAnomalyResultDTO anomaly : anomalies) {
      anomaly.setDetectionConfigId(this.config.getId());
      anomaly.setMetricUrn(this.metricUrn);
      anomaly.setMetric(metric.getName());
      anomaly.setCollection(metric.getDataset());
      anomaly.setDimensions(DetectionUtils.toFilterMap(me.getFilters()));
    }
    return new DetectionPipelineResult(anomalies);
  }

  private AnomalyDetectionStage loadAnomalyDetectorStage(String className) throws Exception {
    return (AnomalyDetectionStage) Class.forName(className).newInstance();
  }

  List<Interval> getMonitoringWindows() {
    if (this.isMovingWindowDetection) {
      try{
        List<Interval> monitoringWindows = new ArrayList<>();
        MetricEntity me = MetricEntity.fromURN(this.metricUrn);
        MetricConfigDTO metricConfigDTO =
            this.provider.fetchMetrics(Collections.singletonList(me.getId())).get(me.getId());
        dataset = this.provider.fetchDatasets(Collections.singletonList(metricConfigDTO.getDataset()))
            .get(metricConfigDTO.getDataset());
        dateTimeZone = DateTimeZone.forID(dataset.getTimezone());
        List<Long> monitoringWindowEndTimes = getMonitoringWindowEndTimes();
        for (long monitoringEndTime : monitoringWindowEndTimes) {
          long endTime = monitoringEndTime - TimeUnit.MILLISECONDS.convert(windowDelay, windowDelayUnit);
          long startTime = endTime - TimeUnit.MILLISECONDS.convert(windowSize, windowUnit);
          monitoringWindows.add(new Interval(startTime, endTime));
        }
        return monitoringWindows;
      } catch (Exception e) {
        LOG.info("can't generate moving monitoring windows, calling with single detection window", e);
      }
    }
    return Collections.singletonList(new Interval(startTime, endTime));
  }

  private List<Long> getMonitoringWindowEndTimes() {
    List<Long> endTimes = new ArrayList<>();

    // get current hour/day, depending on granularity of dataset,
    DateTime currentEndTime = new DateTime(getBoundaryAlignedTimeForDataset(new DateTime(endTime, dateTimeZone)), dateTimeZone);

    DateTime lastDateTime = new DateTime(getBoundaryAlignedTimeForDataset(new DateTime(startTime, dateTimeZone)), dateTimeZone);
    Period bucketSizePeriod = getBucketSizePeriodForDataset();
    while (lastDateTime.isBefore(currentEndTime)) {
      lastDateTime = lastDateTime.plus(bucketSizePeriod);
      endTimes.add(lastDateTime.getMillis());
    }
    return endTimes;
  }

  private long getBoundaryAlignedTimeForDataset(DateTime currentTime) {
    TimeSpec timeSpec = ThirdEyeUtils.getTimeSpecFromDatasetConfig(dataset);
    TimeUnit dataUnit = timeSpec.getDataGranularity().getUnit();

    // For nMINUTE level datasets, with frequency defined in nMINUTES in the function, (make sure size doesnt exceed 30 minutes, just use 1 HOUR in that case)
    // Calculate time periods according to the function frequency
    if (dataUnit.equals(TimeUnit.MINUTES) || dataUnit.equals(TimeUnit.MILLISECONDS) || dataUnit.equals(
        TimeUnit.SECONDS)) {
      if (functionFrequency.getUnit().equals(TimeUnit.MINUTES) && (functionFrequency.getSize() <= 30)) {
        int minuteBucketSize = functionFrequency.getSize();
        int roundedMinutes = (currentTime.getMinuteOfHour() / minuteBucketSize) * minuteBucketSize;
        currentTime = currentTime.withTime(currentTime.getHourOfDay(), roundedMinutes, 0, 0);
      } else {
        currentTime = DetectionJobSchedulerUtils.getBoundaryAlignedTimeForDataset(currentTime,
            TimeUnit.HOURS); // default to HOURS
      }
    } else {
      currentTime = DetectionJobSchedulerUtils.getBoundaryAlignedTimeForDataset(currentTime, dataUnit);
    }

    return currentTime.getMillis();
  }

  public Period getBucketSizePeriodForDataset() {
    Period bucketSizePeriod = null;
    TimeSpec timeSpec = ThirdEyeUtils.getTimeSpecFromDatasetConfig(dataset);
    TimeUnit dataUnit = timeSpec.getDataGranularity().getUnit();

    // For nMINUTE level datasets, with frequency defined in nMINUTES in the function, (make sure size doesnt exceed 30 minutes, just use 1 HOUR in that case)
    // Calculate time periods according to the function frequency
    if (dataUnit.equals(TimeUnit.MINUTES) || dataUnit.equals(TimeUnit.MILLISECONDS) || dataUnit.equals(
        TimeUnit.SECONDS)) {
      if (functionFrequency.getUnit().equals(TimeUnit.MINUTES) && (functionFrequency.getSize() <= 30)) {
        bucketSizePeriod = new Period(0, 0, 0, 0, 0, functionFrequency.getSize(), 0, 0);
      } else {
        bucketSizePeriod = DetectionJobSchedulerUtils.getBucketSizePeriodForUnit(TimeUnit.HOURS); // default to 1 HOUR
      }
    } else {
      bucketSizePeriod = DetectionJobSchedulerUtils.getBucketSizePeriodForUnit(dataUnit);
    }
    return bucketSizePeriod;
  }
}
