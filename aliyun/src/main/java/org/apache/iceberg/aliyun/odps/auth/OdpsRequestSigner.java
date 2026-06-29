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

// Signing logic ported from com.aliyun.odps:odps-sdk-core's AliyunRequestSigner /
// SecurityUtils so this module can be used without pulling in the full ODPS SDK.

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.iceberg.relocated.com.google.common.base.Preconditions;
import org.apache.iceberg.relocated.com.google.common.collect.Maps;

/** Computes the ODPS {@code Authorization} header for a single request. */
final class OdpsRequestSigner {

  static final String HEADER_PREFIX = "x-odps-";
  static final String CONTENT_TYPE = "Content-Type";
  static final String CONTENT_MD5 = "Content-MD5";
  static final String DATE = "Date";

  private static final String NEW_LINE = "\n";
  private static final DateTimeFormatter DATE_FMT =
      DateTimeFormatter.ofPattern("yyyyMMdd", Locale.ROOT);
  private static final DateTimeFormatter RFC1123 =
      DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.ENGLISH);

  private final String accessId;
  private final String accessKey;
  private final String region;
  private final String corporation;
  private final Clock clock;

  OdpsRequestSigner(String accessId, String accessKey, String region, String corporation) {
    this(accessId, accessKey, region, corporation, Clock.systemUTC());
  }

  OdpsRequestSigner(
      String accessId, String accessKey, String region, String corporation, Clock clock) {
    Preconditions.checkArgument(
        accessId != null && !accessId.isEmpty(), "accessId should not be empty");
    Preconditions.checkArgument(
        accessKey != null && !accessKey.isEmpty(), "accessKey should not be empty");
    this.accessId = accessId;
    this.accessKey = accessKey;
    this.region = region;
    this.corporation =
        corporation == null || corporation.isEmpty()
            ? OdpsAuthProperties.CORPORATION_DEFAULT
            : corporation;
    this.clock = clock;
  }

  /**
   * Builds the {@code Authorization} value for an HTTP request. If the {@code Date} header is
   * missing from {@code headers}, the signer generates one using its internal clock and writes it
   * into the map.
   *
   * @param method HTTP method (GET/POST/PUT/DELETE/HEAD)
   * @param resource URI path component, e.g. {@code /api/v1/namespaces/x/tables/y}
   * @param headers mutable request headers; the signer may add {@code Date} if absent
   * @param queryParams query parameters; only those starting with {@code x-odps-} are folded into
   *     the canonical string
   */
  String authorization(
      String method,
      String resource,
      Map<String, String> headers,
      Map<String, String> queryParams) {
    ZonedDateTime signingTime = ensureDateHeader(headers);
    String canonical = canonicalString(method, resource, headers, queryParams);
    if (region == null || region.isEmpty()) {
      return signV2(canonical);
    }
    String scopeDate = signingTime.withZoneSameInstant(ZoneOffset.UTC).format(DATE_FMT);
    return signV4(canonical, scopeDate);
  }

  /** Ensures the Date header is present, generating it from the clock if missing. */
  private ZonedDateTime ensureDateHeader(Map<String, String> headers) {
    String existing = headers.get(DATE);
    if (existing != null) {
      return ZonedDateTime.parse(existing, DateTimeFormatter.RFC_1123_DATE_TIME);
    }
    ZonedDateTime now = ZonedDateTime.now(clock.withZone(ZoneOffset.UTC));
    headers.put(DATE, RFC1123.format(now));
    return now;
  }

  private String signV2(String stringToSign) {
    byte[] sig =
        hmacSha1(
            stringToSign.getBytes(StandardCharsets.UTF_8),
            accessKey.getBytes(StandardCharsets.UTF_8));
    return "ODPS " + accessId + ":" + Base64.getEncoder().encodeToString(sig).trim();
  }

  private String signV4(String stringToSign, String date) {
    String credential =
        accessId + "/" + date + "/" + region + "/odps/" + corporation + "_v4_request";
    byte[] derivedKey = derivedV4Key(date);
    byte[] sig = hmacSha1(stringToSign.getBytes(StandardCharsets.UTF_8), derivedKey);
    return "ODPS " + credential + ":" + Base64.getEncoder().encodeToString(sig);
  }

  private byte[] derivedV4Key(String date) {
    byte[] kSecret = (corporation + "_v4" + accessKey).getBytes(StandardCharsets.UTF_8);
    byte[] kDate = hmacSha256(date.getBytes(StandardCharsets.UTF_8), kSecret);
    byte[] kRegion = hmacSha256(region.getBytes(StandardCharsets.UTF_8), kDate);
    byte[] kService = hmacSha256("odps".getBytes(StandardCharsets.UTF_8), kRegion);
    return hmacSha256((corporation + "_v4_request").getBytes(StandardCharsets.UTF_8), kService);
  }

  static String canonicalString(
      String method,
      String resource,
      Map<String, String> headers,
      Map<String, String> queryParams) {
    StringBuilder builder = new StringBuilder();
    builder.append(method).append(NEW_LINE);

    Map<String, String> headersToSign = Maps.newTreeMap();
    addHeadersToSign(headersToSign, headers);
    headersToSign.putIfAbsent(CONTENT_TYPE.toLowerCase(Locale.ROOT), "");
    headersToSign.putIfAbsent(CONTENT_MD5.toLowerCase(Locale.ROOT), "");

    if (queryParams != null) {
      for (Map.Entry<String, String> e : queryParams.entrySet()) {
        if (e.getKey() != null && e.getKey().startsWith(HEADER_PREFIX)) {
          headersToSign.put(e.getKey(), e.getValue());
        }
      }
    }

    appendCanonicalHeaders(builder, headersToSign);
    builder.append(canonicalResource(resource, queryParams));
    return builder.toString();
  }

  private static void addHeadersToSign(
      Map<String, String> headersToSign, Map<String, String> headers) {
    if (headers == null) {
      return;
    }

    for (Map.Entry<String, String> e : headers.entrySet()) {
      if (e.getKey() == null) {
        continue;
      }

      String lower = e.getKey().toLowerCase(Locale.ROOT);
      if (shouldSignHeader(lower)) {
        headersToSign.put(lower, e.getValue());
      }
    }
  }

  private static boolean shouldSignHeader(String headerName) {
    return headerName.equals(CONTENT_TYPE.toLowerCase(Locale.ROOT))
        || headerName.equals(CONTENT_MD5.toLowerCase(Locale.ROOT))
        || headerName.equals(DATE.toLowerCase(Locale.ROOT))
        || headerName.startsWith(HEADER_PREFIX);
  }

  private static void appendCanonicalHeaders(
      StringBuilder builder, Map<String, String> headersToSign) {
    for (Map.Entry<String, String> entry : headersToSign.entrySet()) {
      String key = entry.getKey();
      String value = entry.getValue();
      if (key.startsWith(HEADER_PREFIX)) {
        builder.append(key).append(':');
        if (value != null) {
          builder.append(value);
        }
      } else {
        builder.append(value == null ? "" : value);
      }
      builder.append(NEW_LINE);
    }
  }

  private static String canonicalResource(String resource, Map<String, String> params) {
    StringBuilder builder = new StringBuilder();
    builder.append(resource);
    if (params != null && !params.isEmpty()) {
      String[] names = params.keySet().toArray(new String[0]);
      Arrays.sort(names);
      char separator = '?';
      for (String name : names) {
        builder.append(separator).append(name);
        String value = params.get(name);
        if (value != null && !value.isEmpty()) {
          builder.append('=').append(value);
        }
        separator = '&';
      }
    }
    return builder.toString();
  }

  private static byte[] hmacSha1(byte[] data, byte[] key) {
    return hmac("HmacSHA1", data, key);
  }

  private static byte[] hmacSha256(byte[] data, byte[] key) {
    return hmac("HmacSHA256", data, key);
  }

  private static byte[] hmac(String algo, byte[] data, byte[] key) {
    try {
      Mac mac = Mac.getInstance(algo);
      mac.init(new SecretKeySpec(key, algo));
      return mac.doFinal(data);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Algorithm not available: " + algo, e);
    } catch (InvalidKeyException e) {
      throw new IllegalStateException("Invalid key for " + algo, e);
    }
  }
}
