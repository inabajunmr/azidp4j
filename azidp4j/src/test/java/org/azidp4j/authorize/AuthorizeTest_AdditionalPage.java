package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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
import org.azidp4j.jwt.JWSIssuer;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.token.SampleIdTokenKidSupplier;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenValidator;
import org.junit.jupiter.api.Test;

class AuthorizeTest_AdditionalPage {

    final ClientStore clientStore = new InMemoryClientStore();
    final Client client = Fixtures.confidentialClient();
    final Client noGrantTypesClient = Fixtures.noGrantTypeClient();
    final Client noResponseTypesClient = Fixtures.noResponseTypeClient();
    final AzIdPConfig config = Fixtures.azIdPConfig();
    final ScopeAudienceMapper scopeAudienceMapper = new SampleScopeAudienceMapper();
    final JWK es256 =
            new ECKeyGenerator(Curve.P_256)
                    .keyID("es")
                    .algorithm(new Algorithm("ES256"))
                    .generate();
    final JWKSet jwks = new JWKSet(es256);

    final Authorize sut =
            new Authorize(
                    clientStore,
                    new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                    scopeAudienceMapper,
                    new InMemoryAccessTokenService(new InMemoryAccessTokenStore()),
                    new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks)),
                    new IDTokenValidator(config, jwks),
                    config);

    public AuthorizeTest_AdditionalPage() throws JOSEException {
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
                            .uiLocales("ja en")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.login, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
            assertEquals(List.of("ja", "en"), response.additionalPage.uiLocales);
        }
        // user not login with id_token_hint
        {
            var jws =
                    new JWSIssuer(jwks)
                            .issue(
                                    "es",
                                    null,
                                    Map.of(
                                            "iss",
                                            config.issuer,
                                            "aud",
                                            client.clientId,
                                            "azp",
                                            client.clientId,
                                            "sub",
                                            "expectedSubject"));
            var authorizationRequest =
                    InternalAuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://rp1.example.com")
                            .scope("rs:scope1")
                            .state("xyz")
                            .uiLocales("ja en")
                            .idTokenHint(jws.serialize())
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.login, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
            assertEquals(List.of("ja", "en"), response.additionalPage.uiLocales);
            assertEquals("expectedSubject", response.additionalPage.expectedUserSubject);
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
                            .authenticatedUserSubject("username")
                            .consentedScope(Set.of())
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.consent, response.additionalPage.prompt);
            assertEquals(Display.popup, response.additionalPage.display);
            assertNull(response.additionalPage.expectedUserSubject);
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
                            .authenticatedUserSubject("username")
                            .consentedScope(Set.of("rs:scope1"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.consent, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
            assertNull(response.additionalPage.expectedUserSubject);
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
                            .authenticatedUserSubject("username")
                            .consentedScope(Set.of("rs:scope1 rs:scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.login, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
            assertNull(response.additionalPage.expectedUserSubject);
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
                            .authenticatedUserSubject("username")
                            .consentedScope(Set.of("rs:scope1 rs:scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.login, response.additionalPage.prompt);
            assertEquals(Display.popup, response.additionalPage.display);
            assertNull(response.additionalPage.expectedUserSubject);
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
                            .authenticatedUserSubject("username")
                            .consentedScope(Set.of("rs:scope1 rs:scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.consent, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
            assertNull(response.additionalPage.expectedUserSubject);
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
            assertNull(response.additionalPage.expectedUserSubject);
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
                            .authenticatedUserSubject("username")
                            .consentedScope(Set.of("rs:scope1 rs:scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.login, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
            assertNull(response.additionalPage.expectedUserSubject);
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
                            .authenticatedUserSubject("username")
                            .consentedScope(Set.of("rs:scope1 rs:scope2"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.select_account, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
            assertNull(response.additionalPage.expectedUserSubject);
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
                            .authenticatedUserSubject("username")
                            .consentedScope(Set.of("openid"))
                            .state("xyz")
                            .build();

            // exercise
            var response = sut.authorize(authorizationRequest);

            // verify
            assertEquals(NextAction.additionalPage, response.next);
            assertEquals(Prompt.login, response.additionalPage.prompt);
            assertEquals(Display.page, response.additionalPage.display);
            assertNull(response.additionalPage.expectedUserSubject);
        }
    }
}
