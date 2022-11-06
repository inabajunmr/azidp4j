package org.azidp4j.token;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.time.Instant;
import java.util.UUID;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenService;
import org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenStore;
import org.azidp4j.token.request.TokenRequest;
import org.azidp4j.util.MapUtil;
import org.junit.jupiter.api.Test;

public class IssueTokenTest {

    @Test
    void validationError() throws JOSEException {

        // setup
        var key = new ECKeyGenerator(Curve.P_256).keyID("123").generate();
        var jwks = new JWKSet(key);
        var authorizationCodeService =
                new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
        var subject = UUID.randomUUID().toString();
        var authorizationCode =
                authorizationCodeService.issue(
                        subject,
                        "rs:scope1",
                        "clientId",
                        "http://example.com",
                        "xyz",
                        null,
                        null,
                        null,
                        null,
                        Instant.now().getEpochSecond() + 600);
        var config = Fixtures.azIdPConfig("kid");
        var clientStore = new InMemoryClientStore();
        var confidentialClient = Fixtures.confidentialClient();
        var noGrantTypeClient = Fixtures.noGrantTypeClient();
        clientStore.save(confidentialClient);
        clientStore.save(noGrantTypeClient);
        var accessTokenStore = new InMemoryAccessTokenStore();
        var issueToken =
                new IssueToken(
                        config,
                        authorizationCodeService,
                        new InMemoryAccessTokenService(accessTokenStore),
                        new IDTokenIssuer(config, jwks, (alg) -> "123"),
                        new InMemoryRefreshTokenService(new InMemoryRefreshTokenStore()),
                        new SampleScopeAudienceMapper(),
                        null,
                        clientStore);

        // type error
        {
            var tokenRequest =
                    new TokenRequest(
                            null,
                            MapUtil.ofNullable(
                                    "code",
                                    1,
                                    "grant_type",
                                    "authorization_code",
                                    "redirect_uri",
                                    "http://example.com",
                                    "client_id",
                                    "not found"));

            // exercise
            var response = issueToken.issue(tokenRequest);

            // verify
            assertEquals(response.body.get("error"), "invalid_request");
        }
        // client not found
        {
            var tokenRequest =
                    new TokenRequest(
                            null,
                            MapUtil.ofNullable(
                                    "code",
                                    authorizationCode.code,
                                    "grant_type",
                                    "authorization_code",
                                    "redirect_uri",
                                    "http://example.com",
                                    "client_id",
                                    "not found"));

            // exercise
            var response = issueToken.issue(tokenRequest);

            // verify
            assertEquals(response.body.get("error"), "unauthorized_client");
        }
        // grant type not supported
        {
            var tokenRequest =
                    new TokenRequest(
                            noGrantTypeClient.clientId,
                            MapUtil.ofNullable(
                                    "grant_type",
                                    "password",
                                    "redirect_uri",
                                    "http://example.com",
                                    "client_id",
                                    noGrantTypeClient.clientId));

            // exercise
            var response = issueToken.issue(tokenRequest);

            // verify
            assertEquals(response.body.get("error"), "unsupported_grant_type");
        }
    }
}
