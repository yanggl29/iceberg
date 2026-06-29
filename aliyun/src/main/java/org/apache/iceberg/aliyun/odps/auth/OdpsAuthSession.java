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

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.apache.iceberg.relocated.com.google.common.base.Preconditions;
import org.apache.iceberg.rest.HTTPHeaders;
import org.apache.iceberg.rest.HTTPHeaders.HTTPHeader;
import org.apache.iceberg.rest.HTTPRequest;
import org.apache.iceberg.rest.ImmutableHTTPHeaders;
import org.apache.iceberg.rest.ImmutableHTTPRequest;
import org.apache.iceberg.rest.auth.AuthSession;

/** Signs each outgoing request with the ODPS V2 or V4 protocol. */
final class OdpsAuthSession implements AuthSession {

  private static final String AUTHORIZATION = "Authorization";

  private final OdpsRequestSigner signer;
  private final String stsToken;

  OdpsAuthSession(OdpsRequestSigner signer) {
    this(signer, null);
  }

  OdpsAuthSession(OdpsRequestSigner signer, String stsToken) {
    this.signer = Preconditions.checkNotNull(signer, "Invalid signer: null");
    this.stsToken = stsToken;
  }

  @Override
  public HTTPRequest authenticate(HTTPRequest request) {
    URI uri = request.requestUri();
    String resource = uri.getPath() == null || uri.getPath().isEmpty() ? "/" : uri.getPath();

    Map<String, String> headerMap = normalizeHeaders(request.headers());
    String authorization =
        signer.authorization(
            request.method().name(), resource, headerMap, request.queryParameters());

    ImmutableHTTPHeaders.Builder builder = ImmutableHTTPHeaders.builder();
    headerMap.forEach((name, value) -> builder.addEntry(HTTPHeader.of(name, value)));
    builder.addEntry(HTTPHeader.of(AUTHORIZATION, authorization));
    if (stsToken != null && !stsToken.isEmpty()) {
      builder.addEntry(HTTPHeader.of(OdpsAuthProperties.STS_TOKEN_HEADER, stsToken));
    }

    HTTPHeaders signedHeaders = builder.build();
    return ImmutableHTTPRequest.builder().from(request).headers(signedHeaders).build();
  }

  private static Map<String, String> normalizeHeaders(HTTPHeaders headers) {
    Map<String, HTTPHeader> normalized = new LinkedHashMap<>();
    headers
        .entries()
        .forEach(
            header -> {
              if (header.name().equalsIgnoreCase(AUTHORIZATION)) {
                return;
              }

              String lowerCaseName = header.name().toLowerCase(Locale.ROOT);
              HTTPHeader existing = normalized.get(lowerCaseName);
              Preconditions.checkArgument(
                  existing == null || existing.value().equals(header.value()),
                  "ODPS auth does not support multiple values for header %s",
                  header.name());
              if (existing == null) {
                normalized.put(
                    lowerCaseName,
                    HTTPHeader.of(canonicalHeaderName(header.name()), header.value()));
              }
            });

    Map<String, String> normalizedValues = new LinkedHashMap<>();
    normalized.values().forEach(header -> normalizedValues.put(header.name(), header.value()));
    return normalizedValues;
  }

  private static String canonicalHeaderName(String name) {
    String lowerCaseName = name.toLowerCase(Locale.ROOT);
    if (OdpsRequestSigner.CONTENT_TYPE.toLowerCase(Locale.ROOT).equals(lowerCaseName)) {
      return OdpsRequestSigner.CONTENT_TYPE;
    }

    if (OdpsRequestSigner.CONTENT_MD5.toLowerCase(Locale.ROOT).equals(lowerCaseName)) {
      return OdpsRequestSigner.CONTENT_MD5;
    }

    if (OdpsRequestSigner.DATE.toLowerCase(Locale.ROOT).equals(lowerCaseName)) {
      return OdpsRequestSigner.DATE;
    }

    return name;
  }

  @Override
  public void close() {}
}
