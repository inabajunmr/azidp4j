package org.azidp4j.sample.handler;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class LoginHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        System.out.println("login");
        System.out.println(exchange.getRequestMethod());

        if (exchange.getRequestMethod().equals("GET")) {
            var query = exchange.getRequestURI().getQuery();
            String loginQuery = "";
            if (query != null) {
                var queryMap =
                        Arrays.stream(query.split("&"))
                                .map(kv -> kv.split("="))
                                .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));
                if (queryMap.containsKey("redirect_to")) {
                    loginQuery = "?redirect_to=" + queryMap.get("redirect_to");
                }
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
                                <form action="/login%QUERY%" method="post">
                                    <input type="text" name="username" placeholder="username">
                                    <input type="password" name="password" placeholder="password">
                                    <button type="submit">login</button>
                                </form>
                            </body>
                            </html>
                    """
                            .replace("%QUERY%", loginQuery)
                            .getBytes(StandardCharsets.UTF_8));
            responseBody.close();
            exchange.close();
        } else if (exchange.getRequestMethod().equals("POST")) {
            var body = new String(exchange.getRequestBody().readAllBytes());
            var bodyMap =
                    Arrays.stream(body.split("&"))
                            .map(kv -> kv.split("="))
                            .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));
            var username = bodyMap.get("username");
            var password = bodyMap.get("password");
            if (username == null || password == null || !verifyPassword(username, password)) {
                exchange.getResponseHeaders()
                        .put("Location", List.of(exchange.getRequestURI().toString()));
                exchange.sendResponseHeaders(302, 0);
                exchange.close();
            }

            // session cookie
            exchange.getResponseHeaders().put("Set-Cookie", List.of("login=" + username));
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
                exchange.getResponseHeaders().put("Location", List.of(redirectTo));
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
    }

    private boolean verifyPassword(String username, String password) {
        switch (username) {
            case "user1":
                return password.equals("password1");
            case "user2":
                return password.equals("password2");
            case "user3":
                return password.equals("password3");
        }
        return false;
    }
}
