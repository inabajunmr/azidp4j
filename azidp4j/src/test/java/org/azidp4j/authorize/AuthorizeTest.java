package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.Set;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.TokenEndpointAuthMethod;
import org.azidp4j.token.accesstoken.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.junit.jupiter.api.Test;

class AuthorizeTest {

    ClientStore clientStore = new InMemoryClientStore();
    Client client =
            new Client(
                    "client1",
                    "clientSecret",
                    Set.of("http://rp1.example.com", "http://rp2.example.com"),
                    Set.of(GrantType.authorization_code),
                    Set.of(ResponseType.code),
                    "scope1 scope2 openid",
                    TokenEndpointAuthMethod.client_secret_basic,
                    SigningAlgorithm.ES256);
    Client noGrantTypesClient =
            new Client(
                    "noGrantTypesClient",
                    "clientSecret",
                    Set.of("http://rp1.example.com"),
                    Set.of(),
                    Set.of(ResponseType.code),
                    "scope1 scope2",
                    TokenEndpointAuthMethod.client_secret_basic,
                    SigningAlgorithm.ES256);

    Client noResponseTypesClient =
            new Client(
                    "noResponseTypesClient",
                    "clientSecret",
                    Set.of("http://rp1.example.com"),
                    Set.of(GrantType.authorization_code, GrantType.implicit),
                    Set.of(),
                    "scope1 scope2",
                    TokenEndpointAuthMethod.client_secret_basic,
                    SigningAlgorithm.ES256);
    AzIdPConfig config = Fixtures.azIdPConfig("kid");
    ;
    Authorize sut =
            new Authorize(
                    clientStore,
                    new InMemoryAuthorizationCodeStore(),
                    new InMemoryAccessTokenStore(),
                    new SampleScopeAudienceMapper(),
                    new IDTokenIssuer(config, new JWKSet()),
                    config);

    public AuthorizeTest() {
        clientStore.save(client);
        clientStore.save(noGrantTypesClient);
        clientStore.save(noResponseTypesClient);
    }

    @Test
    void additionalPage() {

        // user not login
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1")
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.login, response.additionalPage);
        }
        // no consented scope
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of())
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.consent, response.additionalPage);
        }
        // no enough scope consented
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1 scope2")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("scope1"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.consent, response.additionalPage);
        }
        // prompt is login
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1 scope2")
                            .prompt("login")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("scope1 scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.login, response.additionalPage);
        }
        // prompt is consent(authenticated)
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1 scope2")
                            .prompt("consent")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("scope1 scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.consent, response.additionalPage);
        }
        // prompt is consent(not authenticated)
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1 scope2")
                            .prompt("consent")
                            .consentedScope(Set.of("scope1 scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.login, response.additionalPage);
        }
        // prompt is login and consent
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("scope1 scope2")
                            .prompt("login consent")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("scope1 scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(AdditionalPage.login, response.additionalPage);
        }
    }
}
