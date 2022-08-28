package org.azidp4j.sample;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.sun.net.httpserver.HttpServer;
import org.azidp4j.AzIdP;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.sample.handler.AuthorizationEndpointHandler;
import org.azidp4j.sample.handler.JWKsEndpointHandler;
import org.azidp4j.sample.handler.TokenEndpointHandler;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SampleAz {

    private HttpServer server;

    public void start(int port) throws IOException, JOSEException {
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config = new AzIdPConfig(key.getKeyID());
        var azIdP = new AzIdP(config, jwks);
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/authorize", new AuthorizationEndpointHandler(azIdP));
        server.createContext("/token", new TokenEndpointHandler(azIdP));
        server.createContext("/jwks", new JWKsEndpointHandler(jwks));
        ExecutorService pool = Executors.newFixedThreadPool(1);
        server.setExecutor(pool);
        server.start();
    }

    public void stop() {
        server.stop(0);
    }

}

