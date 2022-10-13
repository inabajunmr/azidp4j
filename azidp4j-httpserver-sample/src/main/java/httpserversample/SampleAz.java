package httpserversample;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.sun.net.httpserver.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import httpserversample.authenticator.InnerAccessTokenAuthenticator;
import httpserversample.handler.*;
import org.azidp4j.AzIdP;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.token.UserPasswordVerifier;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.refreshtoken.InMemoryRefreshTokenStore;

public class SampleAz {

    private HttpServer server;
    public AzIdP azIdP;
    private final JWKSet jwks;
    private final ClientStore clientStore;
    private final AccessTokenService accessTokenService;

    public SampleAz() throws JOSEException {

        var rs256 = new RSAKeyGenerator(2048).keyID("abc").algorithm(new Algorithm("RS256")).generate();
        var es256 = new ECKeyGenerator(Curve.P_256).keyID("123").algorithm(new Algorithm("ES256")).generate();
        jwks = new JWKSet(List.of(rs256,es256));
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
                        es256.getKeyID(), 3600, 600, 604800, 3600);
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
        var scopeAudienceMapper= new SampleScopeAudienceMapper();
        accessTokenService = new InMemoryAccessTokenService(new InMemoryAccessTokenStore() );
        azIdP =
                new AzIdP(
                        config,
                        jwks,
                        clientStore,
                        accessTokenService,
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
                .setAuthenticator(new InnerAccessTokenAuthenticator(accessTokenService));
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
