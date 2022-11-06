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
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.client.SigningAlgorithm;
import org.azidp4j.discovery.DiscoveryConfig;
import org.azidp4j.jwt.JWSIssuer;
import org.azidp4j.token.UserPasswordVerifier;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.accesstoken.jwt.JwtAccessTokenService;
import org.azidp4j.token.refreshtoken.jwt.JwtRefreshTokenService;

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
        var discoveryConfig = DiscoveryConfig.builder()
                .authorizationEndpoint("http://localhost:8080/authorize")
                .tokenEndpoint("http://localhost:8080/token")
                .jwksEndpoint("http://localhost:8080/jwks")
                .clientRegistrationEndpoint("http://localhost:8080/client")
                .clientConfigurationEndpointPattern("http://localhost:8080/client/{CLIENT_ID}")
                .userInfoEndpoint("http://localhost:8080/userinfo").build();
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
        accessTokenService = new JwtAccessTokenService(jwks, "http://localhost:8080", es256::getKeyID);
        azIdP = AzIdP.initJwt(es256::getKeyID,es256::getKeyID,es256::getKeyID)
                .issuer("http://localhost:8080")
                .jwkSet(jwks)
                .idTokenKidSupplier((signingAlgorithm -> {
                    if(signingAlgorithm == SigningAlgorithm.ES256) {
                        return es256.getKeyID();
                    }
                    if(signingAlgorithm == SigningAlgorithm.RS256) {
                        return rs256.getKeyID();
                    }
                    throw new AssertionError();
                }))
                .grantTypesSupported(
                        Set.of(
                                GrantType.authorization_code,
                                GrantType.implicit,
                                GrantType.refresh_token,
                                GrantType.password,
                                GrantType.client_credentials))
                .scopesSupported(Set.of("openid", "scope1", "scope2", "scope3", "default"))
                .defaultScopes(Set.of("openid", "scope1"))
                .customClientStore(clientStore)
                .discovery(discoveryConfig)
                .customScopeAudienceMapper(new SampleScopeAudienceMapper())
                .userPasswordVerifier(userPasswordVerifier).build();
    }

    public void start(int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/authorize", new AuthorizationEndpointHandler(azIdP));
        server.createContext("/token", new TokenEndpointHandler(azIdP, clientStore));
        server.createContext("/jwks", new JWKsEndpointHandler(jwks));
        server.createContext("/discovery", new DiscoveryHandler(azIdP));
        server.createContext("/client", new DynamicClientRegistrationHandler(azIdP))
                .setAuthenticator(new InnerAccessTokenAuthenticator(accessTokenService)); // TODO introspect via azidp4j
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
