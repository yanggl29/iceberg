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
package org.apache.iceberg.aliyun.odps.auth;

import java.util.Map;
import java.util.Optional;
import org.apache.iceberg.catalog.SessionCatalog;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.relocated.com.google.common.base.Preconditions;
import org.apache.iceberg.rest.RESTClient;
import org.apache.iceberg.rest.RESTUtil;
import org.apache.iceberg.rest.auth.AuthManager;
import org.apache.iceberg.rest.auth.AuthSession;

/**
 * An {@link AuthManager} that signs every request with the ODPS protocol (V2 or V4).
 *
 * <p>Credential resolution order (similar to AWS DefaultCredentialsProvider):
 *
 * <ol>
 *   <li>Catalog properties: {@code odps.auth.access-key-id} / {@code odps.auth.access-key-secret}
 *   <li>Environment variables: {@code ODPS_ACCESS_KEY_ID} / {@code ODPS_ACCESS_KEY_SECRET}
 * </ol>
 *
 * <p>Configure via:
 *
 * <ul>
 *   <li>{@code rest.auth.type=odps}
 *   <li>{@code odps.auth.access-key-id} / {@code odps.auth.access-key-secret} — or set env vars
 *   <li>{@code odps.auth.region} — optional; presence switches signing from V2 to V4
 *   <li>{@code odps.auth.sts-token} — optional; when set, the AK/SK pair is treated as STS
 *       temporary credentials and the token is sent as the {@code authorization-sts-token} header
 * </ul>
 */
public final class OdpsAuthManager implements AuthManager {

  @SuppressWarnings("unused")
  private final String name;

  private Map<String, String> catalogProperties = Map.of();

  public OdpsAuthManager(String name) {
    this.name = name;
  }

  @Override
  public AuthSession initSession(RESTClient initClient, Map<String, String> properties) {
    return createSession(properties);
  }

  @Override
  public AuthSession catalogSession(RESTClient sharedClient, Map<String, String> properties) {
    this.catalogProperties = properties;
    return createSession(properties);
  }

  @Override
  public AuthSession contextualSession(SessionCatalog.SessionContext context, AuthSession parent) {
    Map<String, String> contextProps =
        RESTUtil.merge(
            Optional.ofNullable(context.properties()).orElseGet(Map::of),
            Optional.ofNullable(context.credentials()).orElseGet(Map::of));
    Map<String, String> merged = RESTUtil.merge(catalogProperties, contextProps);
    return createSession(merged);
  }

  @Override
  public AuthSession tableSession(
      TableIdentifier table, Map<String, String> properties, AuthSession parent) {
    Map<String, String> tableProperties = RESTUtil.merge(catalogProperties, properties);
    return createSession(tableProperties);
  }

  private AuthSession createSession(Map<String, String> properties) {
    String accessId = resolveAccessId(properties);
    String accessKey = resolveAccessKey(properties);
    Preconditions.checkArgument(
        accessId != null && !accessId.isEmpty(),
        "Missing ODPS access key ID. Set property %s or environment variable %s",
        OdpsAuthProperties.ACCESS_KEY_ID,
        OdpsAuthProperties.ENV_ACCESS_KEY_ID);
    Preconditions.checkArgument(
        accessKey != null && !accessKey.isEmpty(),
        "Missing ODPS access key secret. Set property %s or environment variable %s",
        OdpsAuthProperties.ACCESS_KEY_SECRET,
        OdpsAuthProperties.ENV_ACCESS_KEY_SECRET);

    String region = resolveRegion(properties);
    String corporation =
        properties.getOrDefault(
            OdpsAuthProperties.CORPORATION, OdpsAuthProperties.CORPORATION_DEFAULT);
    String stsToken = resolveStsToken(properties);
    return new OdpsAuthSession(
        new OdpsRequestSigner(accessId, accessKey, region, corporation), stsToken);
  }

  private static String resolveAccessId(Map<String, String> properties) {
    String value = properties.get(OdpsAuthProperties.ACCESS_KEY_ID);
    if (value == null || value.isEmpty()) {
      value = System.getenv(OdpsAuthProperties.ENV_ACCESS_KEY_ID);
    }
    return value;
  }

  private static String resolveAccessKey(Map<String, String> properties) {
    String value = properties.get(OdpsAuthProperties.ACCESS_KEY_SECRET);
    if (value == null || value.isEmpty()) {
      value = System.getenv(OdpsAuthProperties.ENV_ACCESS_KEY_SECRET);
    }
    return value;
  }

  private static String resolveRegion(Map<String, String> properties) {
    String value = properties.get(OdpsAuthProperties.REGION);
    if (value == null || value.isEmpty()) {
      value = System.getenv(OdpsAuthProperties.ENV_REGION);
    }
    return value;
  }

  private static String resolveStsToken(Map<String, String> properties) {
    String value = properties.get(OdpsAuthProperties.STS_TOKEN);
    if (value == null || value.isEmpty()) {
      value = System.getenv(OdpsAuthProperties.ENV_STS_TOKEN);
    }
    return value;
  }

  @Override
  public void close() {}
}
