package org.azidp4j.sample;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.sun.net.httpserver.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.azidp4j.AzIdP;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.sample.authenticator.ClientBasicAuthenticator;
import org.azidp4j.sample.authenticator.JWSAccessTokenAuthenticator;
import org.azidp4j.sample.authenticator.UserBasicAuthenticator;
import org.azidp4j.sample.handler.AuthorizationEndpointHandler;
import org.azidp4j.sample.handler.DynamicClientRegistrationHandler;
import org.azidp4j.sample.handler.JWKsEndpointHandler;
import org.azidp4j.sample.handler.TokenEndpointHandler;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.UserPasswordVerifier;

public class SampleAz {

    private HttpServer server;

    public void start(int port) throws IOException, JOSEException {
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config = new AzIdPConfig("issuer", key.getKeyID(), 3600, 604800);
        var clientStore = new InMemoryClientStore();
        var userPasswordVerifier =
                new UserPasswordVerifier() {
                    @Override
                    public boolean verify(String username, String password) {
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
                };
        var azIdP =
                new AzIdP(
                        config,
                        jwks,
                        clientStore,
                        new SampleScopeAudienceMapper(),
                        userPasswordVerifier);
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/authorize", new AuthorizationEndpointHandler(azIdP))
                .setAuthenticator(new UserBasicAuthenticator());
        server.createContext("/token", new TokenEndpointHandler(azIdP))
                .setAuthenticator(new ClientBasicAuthenticator(clientStore));
        server.createContext("/jwks", new JWKsEndpointHandler(jwks));
        server.createContext("/client", new DynamicClientRegistrationHandler(azIdP))
                .setAuthenticator(new JWSAccessTokenAuthenticator(jwks));
        ExecutorService pool = Executors.newFixedThreadPool(1);
        server.setExecutor(pool);
        server.start();
    }

    public void stop() {
        server.stop(0);
    }
}
