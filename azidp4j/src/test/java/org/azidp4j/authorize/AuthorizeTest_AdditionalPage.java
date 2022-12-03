package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.jwk.JWKSet;
import java.time.Instant;
import java.util.Set;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.request.Display;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.request.Prompt;
import org.azidp4j.authorize.response.NextAction;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.token.SampleIdTokenKidSupplier;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.junit.jupiter.api.Test;

class AuthorizeTest_AdditionalPage {

    final ClientStore clientStore = new InMemoryClientStore();
    final Client client = Fixtures.confidentialClient();
    final Client noGrantTypesClient = Fixtures.noGrantTypeClient();
    final Client noResponseTypesClient = Fixtures.noResponseTypeClient();
    final AzIdPConfig config = Fixtures.azIdPConfig("kid");
    final ScopeAudienceMapper scopeAudienceMapper = new SampleScopeAudienceMapper();

    final JWKSet jwks = new JWKSet();

    final Authorize sut =
            new Authorize(
                    clientStore,
                    new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                    scopeAudienceMapper,
                    new InMemoryAccessTokenService(new InMemoryAccessTokenStore()),
                    new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks)),
                    config);

    public AuthorizeTest_AdditionalPage() {
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
                            .scope("rs:scope1")
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.login, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
        }
        // no consented scope
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .authTime(Instant.now().getEpochSecond())
                            .responseType("code")
                            .display("popup")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("rs:scope1")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of())
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.consent, response.additionalPage.prompt);
            assertEquals(Display.popup, response.additionalPage.display);
        }
        // no enough scope consented
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .authTime(Instant.now().getEpochSecond())
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("rs:scope1 rs:scope2")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("rs:scope1"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.consent, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
        }
        // prompt is login(and no display)
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .authTime(Instant.now().getEpochSecond())
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("rs:scope1 rs:scope2")
                            .prompt("login")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("rs:scope1 rs:scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.login, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
        }
        // prompt is login(and display is popup)
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .authTime(Instant.now().getEpochSecond())
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("rs:scope1 rs:scope2")
                            .prompt("login")
                            .display("popup")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("rs:scope1 rs:scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.login, response.additionalPage.prompt);
            assertEquals(Display.popup, response.additionalPage.display);
        }
        // prompt is consent(authenticated)
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .authTime(Instant.now().getEpochSecond())
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("rs:scope1 rs:scope2")
                            .prompt("consent")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("rs:scope1 rs:scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.consent, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
        }
        // prompt is consent(not authenticated)
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("rs:scope1 rs:scope2")
                            .prompt("consent")
                            .consentedScope(Set.of("rs:scope1 rs:scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.login, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
        }
        // prompt is login and consent
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .authTime(Instant.now().getEpochSecond())
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("rs:scope1 rs:scope2")
                            .prompt("login consent")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("rs:scope1 rs:scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.login, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
        }

        // prompt=select_account
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .authTime(Instant.now().getEpochSecond())
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("rs:scope1 rs:scope2")
                            .prompt("select_account")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("rs:scope1 rs:scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.select_account, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
        }

        // user logined but over max age
        {
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .authTime(Instant.now().getEpochSecond() - 11)
                            .maxAge("10")
                            .redirectUri("http://rp1.example.com")
                            .scope("openid")
                            .authenticatedUserId("username")
                            .consentedScope(Set.of("openid"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.login, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
        }
    }
}
