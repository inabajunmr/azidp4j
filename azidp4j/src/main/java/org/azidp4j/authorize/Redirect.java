package org.azidp4j.authorize;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

public class Redirect {

    public final String redirectTo;

    public Redirect(URI redirectUri, Map<String, String> params, ResponseMode responseMode) {
        var uri = new StringBuilder(redirectUri.toString());

        var join =
                params.entrySet().stream()
                        .map(
                                kv ->
                                        kv.getKey()
                                                + '='
                                                + URLEncoder.encode(
                                                        kv.getValue(), StandardCharsets.UTF_8))
                        .collect(Collectors.joining("&"));
        switch (responseMode) {
            case query -> uri.append("?").append(join);
            case fragment -> uri.append("#").append(join);
        }
        this.redirectTo = uri.toString();
    }
}
