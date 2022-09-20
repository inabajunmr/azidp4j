package org.azidp4j.authorize;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

public class AuthorizationResponse {

    public final int status;
    private final Map<String, String> query;
    private final Map<String, String> fragment;
    public final AdditionalPage additionalPage;

    public AuthorizationResponse(
            int status, Map<String, String> query, Map<String, String> fragment) {
        this.status = status;
        this.query =
                query.entrySet().stream()
                        .filter(q -> q.getValue() != null)
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        this.fragment =
                fragment.entrySet().stream()
                        .filter(f -> f.getValue() != null)
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        this.additionalPage = null;
    }

    public AuthorizationResponse(AdditionalPage additionalPage) {
        this.status = 0;
        this.query = null;
        this.fragment = null;
        this.additionalPage = additionalPage;
    }

    public Map<String, String> headers(String redirectTo) {
        var uri = new StringBuilder(redirectTo);
        if (!query.entrySet().isEmpty()) {
            var queryResponse =
                    query.entrySet().stream()
                            .map(
                                    kv ->
                                            kv.getKey()
                                                    + '='
                                                    + URLEncoder.encode(
                                                            kv.getValue(), StandardCharsets.UTF_8))
                            .collect(Collectors.joining("&"));
            uri.append("?").append(queryResponse);
        }

        if (!fragment.entrySet().isEmpty()) {
            var fragmentResponse =
                    fragment.entrySet().stream()
                            .map(
                                    kv ->
                                            kv.getKey()
                                                    + '='
                                                    + URLEncoder.encode(
                                                            kv.getValue(), StandardCharsets.UTF_8))
                            .collect(Collectors.joining("&"));
            uri.append("#").append(fragmentResponse);
        }
        return Map.of("Location", uri.toString());
    }
}
