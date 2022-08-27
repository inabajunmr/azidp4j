package org.azidp4j.sample.handler;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.azidp4j.AzIdP;
import org.azidp4j.jwt.jwks.JWKSupplier;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class JWKsEndpointHandler implements HttpHandler {

    private final JWKSupplier jwkSupplier;

    public JWKsEndpointHandler(JWKSupplier jwkSupplier) {
        this.jwkSupplier = jwkSupplier;
    }

    @Override
    public void handle(HttpExchange httpExchange) throws IOException {
        var jwksJSON = jwkSupplier.publicJwks().toString(true);
        httpExchange.getResponseHeaders().set("Content-Type", "application/json");
        httpExchange.sendResponseHeaders(200, jwksJSON.getBytes(StandardCharsets.UTF_8).length);
        var os = httpExchange.getResponseBody();
        os.write(jwksJSON.getBytes(StandardCharsets.UTF_8));
        os.close();
        httpExchange.close();
    }
}
