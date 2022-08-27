package org.azidp4j.sample;

import com.sun.net.httpserver.HttpServer;
import org.azidp4j.AzIdP;
import org.azidp4j.jwt.jwks.JWKSupplier;
import org.azidp4j.sample.handler.AuthorizationEndpointHandler;
import org.azidp4j.sample.handler.JWKsEndpointHandler;
import org.azidp4j.sample.handler.TokenEndpointHandler;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SampleAz {

    private HttpServer server;

    public void start(int port) throws IOException {
        var jwkSupplier = new JWKSupplier();
        var azIdP = new AzIdP(jwkSupplier);
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/authorize", new AuthorizationEndpointHandler(azIdP));
        server.createContext("/token", new TokenEndpointHandler(azIdP));
        server.createContext("/jwks", new JWKsEndpointHandler(jwkSupplier));
        ExecutorService pool = Executors.newFixedThreadPool(1);
        server.setExecutor(pool);
        server.start();
    }

    public void stop() {
        server.stop(0);
    }

}

