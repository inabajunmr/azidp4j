package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.nimbusds.jose.jwk.JWKSet;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.request.Prompt;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.authorize.response.NextAction;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.token.SampleIdTokenKidSupplier;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenValidator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class AuthorizeTest_Acr {

    final ClientStore clientStore = new InMemoryClientStore();
    final Client clientWithDefaultAcrValues =
            Fixtures.confidentialClient().defaultAcrValues(List.of("acr1", "acr2")).build();
    final Client clientWithoutDefaultAcrValues =
            Fixtures.confidentialClient().defaultAcrValues(null).build();
    final AzIdPConfig configWithSupportedAcrValues = Fixtures.azIdPConfig();
    final AzIdPConfig configWithoutSupportedAcrValues =
            new AzIdPConfig(
                    "http://localhost:8080",
                    Set.of("openid", "rs:scope1", "rs:scope2", "rs:scope3", "default"),
                    Set.of("openid", "rs:scope1"),
                    Set.of(TokenEndpointAuthMethod.client_secret_basic),
                    null,
                    Set.of(TokenEndpointAuthMethod.client_secret_basic),
                    null,
                    Set.of(TokenEndpointAuthMethod.client_secret_basic),
                    null,
                    Set.of(
                            GrantType.authorization_code,
                            GrantType.implicit,
                            GrantType.password,
                            GrantType.client_credentials,
                            GrantType.refresh_token),
                    Set.of(
                            Set.of(ResponseType.code),
                            Set.of(ResponseType.token),
                            Set.of(ResponseType.id_token),
                            Set.of(ResponseType.code, ResponseType.token),
                            Set.of(ResponseType.code, ResponseType.id_token),
                            Set.of(ResponseType.token, ResponseType.id_token),
                            Set.of(ResponseType.code, ResponseType.token, ResponseType.id_token)),
                    Set.of(ResponseMode.query, ResponseMode.fragment),
                    Set.of(SigningAlgorithm.ES256, SigningAlgorithm.RS256, SigningAlgorithm.none),
                    List.of("acr1", "acr2"),
                    Duration.ofSeconds(3600),
                    Duration.ofSeconds(600),
                    Duration.ofSeconds(604800),
                    Duration.ofSeconds(3600));
    final ScopeAudienceMapper scopeAudienceMapper = new SampleScopeAudienceMapper();
    final InMemoryAuthorizationCodeService inMemoryAuthorizationCodeService =
            new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore());
    final JWKSet jwks = new JWKSet();
    final Authorize withoutSupportedValues =
            new Authorize(
                    clientStore,
                    inMemoryAuthorizationCodeService,
                    scopeAudienceMapper,
                    new InMemoryAccessTokenService(new InMemoryAccessTokenStore()),
                    new IDTokenIssuer(
                            configWithoutSupportedAcrValues,
                            jwks,
                            new SampleIdTokenKidSupplier(jwks),
                            null),
                    new IDTokenValidator(configWithoutSupportedAcrValues, jwks),
                    configWithoutSupportedAcrValues);
    final Authorize withSupportedValues =
            new Authorize(
                    clientStore,
                    inMemoryAuthorizationCodeService,
                    scopeAudienceMapper,
                    new InMemoryAccessTokenService(new InMemoryAccessTokenStore()),
                    new IDTokenIssuer(
                            configWithSupportedAcrValues,
                            jwks,
                            new SampleIdTokenKidSupplier(jwks),
                            null),
                    new IDTokenValidator(configWithSupportedAcrValues, jwks),
                    configWithSupportedAcrValues);

    public AuthorizeTest_Acr() {
        clientStore.save(clientWithDefaultAcrValues);
        clientStore.save(clientWithoutDefaultAcrValues);
    }

    @Test
    @DisplayName("supportedAcrValues=acr1, acr2 | acr_values=unsupported | requested acr=null")
    void authorizationCodeGrant_SupportedAcrValuesAndRequestAcrValuesUnmatched() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .acrValues("unsupported") // target
                        .clientId(clientWithDefaultAcrValues.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("https://rp1.example.com")
                        .scope("rs:scope1")
                        .state("xyz")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .build();

        // exercise
        var response = withSupportedValues.authorize(authorizationRequest);

        // verify
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("invalid_request", queryMap.get("error"));
        assertEquals(response.errorDescription, "acrValues has unsupported value");
    }

    @Test
    @DisplayName(
            "supportedAcrValues=acr1, acr2 | acr_values=null | defaultArcValues=unsupported |"
                    + " requested acr=null")
    void authorizationCodeGrant_SupportedAcrValuesAndDefaultAcrValuesUnmatched() {
        // setup
        var clientWithUnsupportedDefaultAcrValues =
                Fixtures.confidentialClient().defaultAcrValues(List.of("unsupported")).build();
        clientStore.save(clientWithUnsupportedDefaultAcrValues);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(clientWithUnsupportedDefaultAcrValues.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("https://rp1.example.com")
                        .scope("rs:scope1")
                        .state("xyz")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .build();

        // exercise
        var response = withSupportedValues.authorize(authorizationRequest);

        // verify
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("invalid_request", queryMap.get("error"));
        assertEquals(response.errorDescription, "acrValues has unsupported value");
    }

    @Test
    @DisplayName(
            "supportedAcrValues=null | acr_values=null | defaultArcValues=null | requested"
                    + " acr=null")
    void authorizationCodeGrant_NoSupportedAcrValuesNoAcrValuesNoDefault() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(clientWithoutDefaultAcrValues.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("https://rp1.example.com")
                        .scope("rs:scope1")
                        .state("xyz")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .build();

        // exercise
        var response = withoutSupportedValues.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertNotNull(queryMap.get("code"));
        var authorizationCode = inMemoryAuthorizationCodeService.consume(queryMap.get("code"));
        assertNull(authorizationCode.get().acr);
    }

    @Test
    @DisplayName(
            "supportedAcrValues=null | acr_values=null | defaultArcValues=null | requested"
                    + " acr=acrValue")
    void authorizationCodeGrant_NoSupportedAcrValuesNoAcrValuesNoDefaultAcrSpecified() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(clientWithoutDefaultAcrValues.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("https://rp1.example.com")
                        .scope("rs:scope1")
                        .state("xyz")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .authenticatedUserAcr("acrValue")
                        .build();

        // exercise
        var response = withoutSupportedValues.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertNotNull(queryMap.get("code"));
        var authorizationCode = inMemoryAuthorizationCodeService.consume(queryMap.get("code"));
        assertEquals("acrValue", authorizationCode.get().acr);
    }

    @Test
    @DisplayName(
            "supportedAcrValues=acr1,acr2 | acr_values=null | defaultArcValues=null | requested"
                    + " acr=acrValue")
    void authorizationCodeGrant_SupportedAcrSpecifiedValuesNoAcrValuesNoDefaultAcrSpecified() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(clientWithoutDefaultAcrValues.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("https://rp1.example.com")
                        .scope("rs:scope1")
                        .state("xyz")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .authenticatedUserAcr("acrValue")
                        .build();

        // exercise
        var response = withSupportedValues.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertNotNull(queryMap.get("code"));
        var authorizationCode = inMemoryAuthorizationCodeService.consume(queryMap.get("code"));
        assertEquals("acrValue", authorizationCode.get().acr);
    }

    @Test
    @DisplayName(
            "supportedAcrValues=acr1,acr2 | acr_values=acr1 | defaultArcValues=null | requested"
                    + " acr=acr2")
    void authorizationCodeGrant_AcrValuesAndUserAcrUnmatched() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(clientWithoutDefaultAcrValues.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("https://rp1.example.com")
                        .scope("rs:scope1")
                        .state("xyz")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .authenticatedUserAcr("acr2") // target
                        .acrValues("acr1") // target
                        .build();

        // exercise
        var response = withSupportedValues.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.additionalPage);
        assertEquals(Prompt.login, response.additionalPage().prompt);
        assertEquals(List.of("acr1"), response.additionalPage().acrValues);
    }

    @Test
    @DisplayName(
            "supportedAcrValues=acr1,acr2 | acr_values=acr1 | defaultArcValues=null | requested"
                    + " acr=acr1")
    void authorizationCodeGrant_AcrValuesAndUserAcrMatched() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(clientWithoutDefaultAcrValues.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("https://rp1.example.com")
                        .scope("rs:scope1")
                        .state("xyz")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .authenticatedUserAcr("acr1") // target
                        .acrValues("acr1") // target x
                        .build();

        // exercise
        var response = withSupportedValues.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertNotNull(queryMap.get("code"));
        var authorizationCode = inMemoryAuthorizationCodeService.consume(queryMap.get("code"));
        assertEquals("acr1", authorizationCode.get().acr);
    }

    @Test
    @DisplayName(
            "supportedAcrValues=acr1,acr2 | acr_values=acr1 | defaultArcValues=acr1 | requested"
                    + " acr=acr1")
    void authorizationCodeGrant_AcrValuesAndClientDefaultMatched() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(clientWithDefaultAcrValues.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("https://rp1.example.com")
                        .scope("rs:scope1")
                        .state("xyz")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .authenticatedUserAcr("acr1") // target
                        .build();

        // exercise
        var response = withSupportedValues.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertNotNull(queryMap.get("code"));
        var authorizationCode = inMemoryAuthorizationCodeService.consume(queryMap.get("code"));
        assertEquals("acr1", authorizationCode.get().acr);
    }

    @Test
    @DisplayName(
            "supportedAcrValues=acr1,acr2 | acr_values=acr2 | defaultArcValues=acr1 | requested"
                    + " acr=null")
    void authorizationCodeGrant_AcrValuesAndClientDefaultUnmatched() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(clientWithDefaultAcrValues.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("https://rp1.example.com")
                        .scope("rs:scope1")
                        .state("xyz")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .acrValues("acr2")
                        .build();

        // exercise
        var response = withSupportedValues.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.additionalPage);
        assertEquals(Prompt.login, response.additionalPage().prompt);
        assertEquals(List.of("acr2"), response.additionalPage().acrValues);
    }

    @Test
    @DisplayName(
            "supportedAcrValues=acr1,acr2 | acr_values=acr1 | defaultArcValues=acr1 | requested"
                    + " acr=acr3")
    void authorizationCodeGrant_AcrValuesAndClientDefaultMatchedButUserAcrUnmatched() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(clientWithDefaultAcrValues.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("https://rp1.example.com")
                        .scope("rs:scope1")
                        .state("xyz")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .authenticatedUserAcr("acr3") // target
                        .acrValues("acr1")
                        .build();

        // exercise
        var response = withSupportedValues.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.additionalPage);
        assertEquals(Prompt.login, response.additionalPage().prompt);
        assertEquals(List.of("acr1"), response.additionalPage().acrValues);
    }

    @Test
    @DisplayName(
            "supportedAcrValues=acr1,acr2 | acr_values=acr2 | defaultArcValues=acr1 | requested"
                    + " acr=acr2")
    void authorizationCodeGrant_AcrValuesAndClientDefaultUnmatchedButUserAcrMatched() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(clientWithDefaultAcrValues.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("https://rp1.example.com")
                        .scope("rs:scope1")
                        .state("xyz")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .authenticatedUserAcr("acr2") // target
                        .acrValues("acr2") // target
                        .build();

        // exercise
        var response = withSupportedValues.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertNotNull(queryMap.get("code"));
        var authorizationCode = inMemoryAuthorizationCodeService.consume(queryMap.get("code"));
        assertEquals("acr2", authorizationCode.get().acr);
    }
}
