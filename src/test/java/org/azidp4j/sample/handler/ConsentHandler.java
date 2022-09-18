package org.azidp4j.sample.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.azidp4j.sample.web.CookieParser;

public class ConsentHandler extends AzIdpHttpHandler {

    @Override
    public void process(HttpExchange exchange) throws IOException {
        if (exchange.getRequestMethod().equals("GET")) {
            responseForm(exchange);
        } else if (exchange.getRequestMethod().equals("POST")) {
            consent(exchange);
        }
    }

    private void consent(HttpExchange exchange) throws IOException {
        var body = new String(exchange.getRequestBody().readAllBytes());
        var bodyMap =
                Arrays.stream(body.split("&"))
                        .map(kv -> kv.split("="))
                        .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));
        var clientId = bodyMap.get("client_id");
        var scope = bodyMap.get("scope");
        if (clientId == null || scope == null) {
            exchange.sendResponseHeaders(400, 0);
            exchange.close();
            return;
        }
        var cookies = CookieParser.parse(exchange);
        ObjectNode userAuthenticatedScope;
        if (cookies.containsKey("Consent")) {
            var consent = new ObjectMapper().readTree(cookies.get("Consent"));
            if (consent.has(clientId)) {
                var consentedScope = consent.get(clientId).asText();
                // merge
                userAuthenticatedScope = (ObjectNode) consent;
                userAuthenticatedScope.replace(
                        clientId,
                        TextNode.valueOf(
                                Arrays.stream((consentedScope + " " + scope).trim().split(" "))
                                        .distinct()
                                        .collect(Collectors.joining(" "))));
            } else {
                userAuthenticatedScope = JsonNodeFactory.instance.objectNode();
                userAuthenticatedScope.set(clientId, TextNode.valueOf(scope));
            }
        } else {
            userAuthenticatedScope = JsonNodeFactory.instance.objectNode();
            userAuthenticatedScope.set(clientId, TextNode.valueOf(scope));
        }

        // session cookie
        exchange.getResponseHeaders()
                .put(
                        "Set-Cookie",
                        List.of(
                                "Consent="
                                        + new ObjectMapper()
                                                .writeValueAsString(userAuthenticatedScope)));
        var query = exchange.getRequestURI().getQuery();
        String redirectTo = null;
        if (query != null) {
            var queryMap =
                    Arrays.stream(query.split("&"))
                            .map(kv -> kv.split("="))
                            .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));
            redirectTo = queryMap.get("redirect_to");
        }
        if (redirectTo != null) {
            exchange.getResponseHeaders()
                    .put(
                            "Location",
                            List.of(URLDecoder.decode(redirectTo, StandardCharsets.UTF_8)));
            exchange.sendResponseHeaders(302, 0);
            exchange.close();
        }
        exchange.getResponseHeaders().put("Content-Type", List.of("text/html"));
        exchange.sendResponseHeaders(200, 0);

        var responseBody = exchange.getResponseBody();
        responseBody.write(
                """
                            <!DOCTYPE html>
                            <html lang="en">
                            <head>
                                <meta charset="UTF-8">
                                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Login</title>
                            </head>
                            <body>
                                Logined!
                            </body>
                            </html>
                    """
                        .getBytes(StandardCharsets.UTF_8));
        responseBody.close();
        exchange.close();
    }

    private static void responseForm(HttpExchange exchange) throws IOException {

        var query = exchange.getRequestURI().getQuery();
        String consentQuery = "";
        String scope = "";
        String clientId = "";

        if (query != null) {
            var queryMap =
                    Arrays.stream(query.split("&"))
                            .map(kv -> kv.split("="))
                            .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));
            if (queryMap.containsKey("redirect_to")) {
                consentQuery =
                        "?redirect_to="
                                + URLEncoder.encode(
                                        queryMap.get("redirect_to"), StandardCharsets.UTF_8);
            }
            if (!queryMap.containsKey("client_id") || !queryMap.containsKey("scope")) {
                exchange.sendResponseHeaders(400, 0);
                exchange.close();
                return;
            }
            scope = queryMap.get("scope");
            clientId = queryMap.get("client_id");
        }
        var responseBody = exchange.getResponseBody();
        exchange.getResponseHeaders().put("Content-Type", List.of("text/html"));
        exchange.sendResponseHeaders(200, 0);
        responseBody.write(
                """
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta http-equiv="X-UA-Compatible" content="IE=edge">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>Login</title>
                        </head>
                        <body>
                            <form action="/consent%QUERY%" method="post">
                                <input type="hidden" name="client_id" value="%CLIENT_ID%">
                                <input type="hidden" name="scope" value="%SCOPE%">
                                <button type="submit">consent</button>
                            </form>
                        </body>
                        </html>
                """
                        .replace("%QUERY%", consentQuery)
                        .replace("%CLIENT_ID%", clientId)
                        .replace("%SCOPE", scope)
                        .getBytes(StandardCharsets.UTF_8));
        responseBody.close();
        exchange.close();
    }
}
