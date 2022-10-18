package org.azidp4j.token;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.AuthorizationCode;
import org.azidp4j.authorize.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenStore;
import org.azidp4j.token.request.InternalTokenRequest;
import org.junit.jupiter.api.Test;

public class IssueTokenTest {

    @Test
    void validationError() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore();
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                new AuthorizationCode(
                        subject,
                        UUID.randomUUID().toString(),
                        "scope1",
                        "clientId",
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        authorizationCodeStore.save(authorizationCode);
        var config = Fixtures.azIdPConfig("kid");
        var clientStore = new InMemoryClientStore();
        clientStore.save(
                new Client(
                        "clientId",
                        "secret",
                        null,
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "scope1 scope2",
                        TokenEndpointAuthMethod.client_secret_basic,
                        SigningAlgorithm.ES256));
        var accessTokenStore = new InMemoryAccessTokenStore();
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeStore,
                        new InMemoryAccessTokenService(accessTokenStore),
                        new IDTokenIssuer(config, jwks),
                        new InMemoryRefreshTokenService(new InMemoryRefreshTokenStore()),
                        new SampleScopeAudienceMapper(),
                        null,
                        clientStore);

        // client not found
        {
            var tokenRequest =
                    InternalTokenRequest.builder()
                            .code(authorizationCode.code)
                            .grantType("authorization_code")
                            .redirectUri("http://example.com")
                            .clientId("not found")
                            .build();

            // exercise
            var response = issueToken.issue(tokenRequest);

            // verify
            assertEquals(response.body.get("error"), "unauthorized_client");
        }
        // grant type not supported
        {
            var tokenRequest =
                    InternalTokenRequest.builder()
                            .grantType("password")
                            .redirectUri("http://example.com")
                            .clientId("clientId")
                            .authenticatedClientId("clientId")
                            .build();

            // exercise
            var response = issueToken.issue(tokenRequest);

            // verify
            assertEquals(response.body.get("error"), "unsupported_grant_type");
        }
    }
}
