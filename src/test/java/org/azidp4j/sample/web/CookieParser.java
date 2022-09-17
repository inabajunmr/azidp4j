package org.azidp4j.sample.web;

import com.sun.net.httpserver.HttpExchange;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public class CookieParser {

    public static Map<String, String> parse(HttpExchange exchange) {
        if (exchange.getRequestHeaders().get("cookie") == null) {
            return Map.of();
        }
        var cookie = exchange.getRequestHeaders().get("Cookie").get(0);
        if (cookie == null) {
            return Map.of();
        }
        return Arrays.stream(cookie.split(";"))
                .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
    }
}
