package httpserversample;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.sun.net.httpserver.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import httpserversample.handler.*;
import org.azidp4j.AzIdP;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.InMemoryClientStore;
import httpserversample.authenticator.JWSAccessTokenAuthenticator;
import org.azidp4j.token.UserPasswordVerifier;
import org.azidp4j.token.refreshtoken.InMemoryRefreshTokenStore;

public class SampleAz {

    private HttpServer server;
    public AzIdP azIdP;
    private final JWKSet jwks;
    private final ClientStore clientStore;

    public SampleAz() throws JOSEException {

        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        jwks = new JWKSet(key);
        var config =
                new AzIdPConfig(
                        "http://localhost:8080",
                        "http://localhost:8080/authorize",
                        "http://localhost:8080/token",
                        "http://localhost:8080/jwks",
                        "http://localhost:8080/client",
                        "http://localhost:8080/client/{CLIENT_ID}",
                        "http://localhost:8080/userinfo",
                        Set.of("openid", "scope1", "scope2", "default"),
                        key.getKeyID(), key.getKeyID(), 3600, 600, 604800, 3600);
        clientStore = new InMemoryClientStore();
        var userPasswordVerifier =
                new UserPasswordVerifier() {
                    @Override
                    public boolean verify(String username, String password) {
                        return switch (username) {
                            case "user1" -> password.equals("password1");
                            case "user2" -> password.equals("password2");
                            case "user3" -> password.equals("password3");
                            default -> false;
                        };
                    }
                };
        azIdP =
                new AzIdP(
                        config,
                        jwks,
                        clientStore,
                        new InMemoryRefreshTokenStore(),
                        new SampleScopeAudienceMapper(),
                        userPasswordVerifier);
    }

    public void start(int port) throws IOException, JOSEException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/authorize", new AuthorizationEndpointHandler(azIdP));
        server.createContext("/token", new TokenEndpointHandler(azIdP, clientStore));
        server.createContext("/jwks", new JWKsEndpointHandler(jwks));
        server.createContext("/discovery", new DiscoveryHandler(azIdP));
        server.createContext("/client", new DynamicClientRegistrationHandler(azIdP))
                .setAuthenticator(new JWSAccessTokenAuthenticator(jwks));
        server.createContext("/login", new LoginHandler());
        server.createContext("/consent", new ConsentHandler());
        ExecutorService pool = Executors.newFixedThreadPool(1);
        server.setExecutor(pool);
        server.start();
    }

    public void stop() {
        server.stop(0);
    }
}