package org.azidp4j.springsecuritysample;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import org.azidp4j.AzIdP;
import org.azidp4j.client.ClientRegistrationRequest;
import org.azidp4j.client.ClientStore;
import org.azidp4j.token.UserPasswordVerifier;
import org.azidp4j.token.accesstoken.AccessTokenStore;
import org.azidp4j.token.refreshtoken.InMemoryRefreshTokenStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.provisioning.UserDetailsManager;

@Configuration
public class AzIdPConfig {

    @Autowired UserDetailsManager userDetailsManager;

    @Value("${endpoint}")
    private String endpoint;

    @Bean
    public AzIdP azIdP(ClientStore clientStore, JWKSet jwkSet, AccessTokenStore accessTokenStore)
            throws JOSEException {
        var key = jwkSet.getKeys().get(0);
        var config =
                new org.azidp4j.AzIdPConfig(
                        endpoint,
                        endpoint + "/authorize",
                        endpoint + "/token",
                        endpoint + "/.well-known/jwks.json",
                        endpoint + "/client",
                        endpoint + "/client/{CLIENT_ID}",
                        endpoint + "/userinfo",
                        Set.of("openid", "scope1", "scope2", "default"),
                        key.getKeyID(),
                        3600,
                        600,
                        604800,
                        3600);
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
        var azIdp =
                new AzIdP(
                        config,
                        jwkSet,
                        clientStore,
                        accessTokenStore,
                        new InMemoryRefreshTokenStore(),
                        scope -> Set.of("rs.example.com"),
                        userPasswordVerifier);
        var clientRegistration =
                ClientRegistrationRequest.builder()
                        .redirectUris(
                                Set.of(
                                        "http://client.example.com/callback1",
                                        "http://client.example.com/callback2"))
                        .grantTypes(
                                Set.of(
                                        "authorization_code",
                                        "implicit",
                                        "refresh_token",
                                        "client_credentials"))
                        .scope("scope1 scope2 openid client")
                        .responseTypes(Set.of("code", "token", "id_token"))
                        .tokenEndpointAuthMethod("client_secret_basic")
                        .build();
        var client = azIdp.registerClient(clientRegistration);
        System.out.println(client.body);
        System.out.println(
                endpoint
                        + "/authorize?response_type=code&client_id="
                        + client.body.get("client_id")
                        + "&redirect_uri="
                        + URLEncoder.encode(
                                "http://client.example.com/callback1", StandardCharsets.UTF_8)
                        + "&scope=scope1");
        System.out.println(
                "curl -X POST -u "
                        + client.body.get("client_id")
                        + ":"
                        + client.body.get("client_secret")
                        + " -d 'grant_type=authorization_code' -d"
                        + " 'redirect_uri=http://client.example.com/callback1' -d 'code=xxx'"
                        + " "
                        + endpoint
                        + "token");
        return azIdp;
    }

    @Bean
    public JWKSet jwkSet() throws JOSEException {
        var es256 =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("123")
                        .algorithm(new Algorithm("ES256"))
                        .generate();
        var rs256 =
                new RSAKeyGenerator(2048).keyID("abc").algorithm(new Algorithm("RS256")).generate();
        return new JWKSet(List.of(es256, rs256));
    }
}
