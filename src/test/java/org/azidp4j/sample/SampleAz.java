package org.azidp4j.sample;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.sun.net.httpserver.*;
import org.azidp4j.AzIdP;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.sample.handler.AuthorizationEndpointHandler;
import org.azidp4j.sample.handler.DynamicClientRegistrationHandler;
import org.azidp4j.sample.handler.JWKsEndpointHandler;
import org.azidp4j.sample.handler.TokenEndpointHandler;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.text.ParseException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SampleAz {

    private HttpServer server;

    public void start(int port) throws IOException, JOSEException {
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var config = new AzIdPConfig("issuer", key.getKeyID());
        var clientStore = new InMemoryClientStore();
        var azIdP = new AzIdP(config, jwks, clientStore);
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/authorize", new AuthorizationEndpointHandler(azIdP));
        var context = server.createContext("/token", new TokenEndpointHandler(azIdP, clientStore));
        context.setAuthenticator(new BasicAuthenticator("token endpoint") {
            @Override
            public boolean checkCredentials(String username, String secret) {
                var client = clientStore.find(username);
                if(client == null) {
                    return false;
                }
                if(client.clientSecret.equals(secret)) {
                    return true;
                }
                return false;
            }
        });
        server.createContext("/jwks", new JWKsEndpointHandler(jwks));
        server.createContext("/client", new DynamicClientRegistrationHandler(azIdP)).setAuthenticator(new Authenticator() {
            @Override
            public Result authenticate(HttpExchange httpExchange) {
                var authorization = httpExchange.getRequestHeaders().get("Authorization").get(0);
                if(!authorization.startsWith("Bearer ")) {
                    return new Failure(403);
                }
                var token = authorization.replaceAll("^Bearer ", "");
                try {
                    var parsedToken = JWSObject.parse(token);
                    var key = (ECKey)jwks.toPublicJWKSet().getKeyByKeyId(parsedToken.getHeader().getKeyID());
                    if(parsedToken.verify(new ECDSAVerifier(key))) {
                        if(parsedToken.getPayload().toJSONObject().get("scope").equals("default")) {
                            return new Success(new HttpPrincipal(
                                    parsedToken.getPayload().toJSONObject().get("sub").toString(),
                                    "client registration"));
                        };
                    } else {
                        return new Failure(403);
                    }
                } catch (ParseException | JOSEException e) {
                    return new Failure(403);
                }
                return null;
            }
        });
        ExecutorService pool = Executors.newFixedThreadPool(1);
        server.setExecutor(pool);
        server.start();
    }

    public void stop() {
        server.stop(0);
    }
}

