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

public final class OdpsAuthProperties {

  private OdpsAuthProperties() {}

  /** AccessKey ID. Required. */
  public static final String ACCESS_KEY_ID = "odps.auth.access-key-id";

  /** AccessKey secret. Required. */
  public static final String ACCESS_KEY_SECRET = "odps.auth.access-key-secret";

  /**
   * Optional region. When set, signing uses ODPS V4 (HMAC-SHA256 derived key, HMAC-SHA1 final
   * signature). When empty, signing falls back to ODPS V2 (HMAC-SHA1, no region).
   */
  public static final String REGION = "odps.auth.region";

  /**
   * Optional. The corporation tag baked into V4 credential scope, default {@code aliyun}. Only
   * change this if you are talking to a non-public ODPS service that uses a different tag.
   */
  public static final String CORPORATION = "odps.auth.corporation";

  public static final String CORPORATION_DEFAULT = "aliyun";

  /**
   * Optional STS security token. When set, the supplied {@link #ACCESS_KEY_ID} / {@link
   * #ACCESS_KEY_SECRET} are treated as temporary STS credentials, and the token is sent as the
   * {@code authorization-sts-token} header alongside the V2/V4 {@code Authorization} header. The
   * token itself does not participate in the canonical signing string — server-side validation of
   * the STS token is independent of the request signature.
   */
  public static final String STS_TOKEN = "odps.auth.sts-token";

  /** HTTP header carrying the STS security token. */
  public static final String STS_TOKEN_HEADER = "authorization-sts-token";

  // -- Environment variable names (fallback when properties are not set) --

  /** Environment variable for access key ID. */
  public static final String ENV_ACCESS_KEY_ID = "ODPS_ACCESS_KEY_ID";

  /** Environment variable for access key secret. */
  public static final String ENV_ACCESS_KEY_SECRET = "ODPS_ACCESS_KEY_SECRET";

  /** Environment variable for region. */
  public static final String ENV_REGION = "ODPS_REGION";

  /** Environment variable for STS token. */
  public static final String ENV_STS_TOKEN = "ODPS_STS_TOKEN";
}
