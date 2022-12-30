package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeStore;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.authorize.response.AuthorizationErrorTypeWithoutRedirect;
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

class AuthorizeTest_ValidationError {

    final ClientStore clientStore = new InMemoryClientStore();
    final Client client = Fixtures.confidentialClient();
    final Client authorizationCodeClient = Fixtures.authorizationCodeClient();
    final Client noGrantTypesClient = Fixtures.noGrantTypeClient();
    final Client noResponseTypesClient = Fixtures.noResponseTypeClient();
    final AzIdPConfig config = Fixtures.azIdPConfig();
    final ScopeAudienceMapper scopeAudienceMapper = new SampleScopeAudienceMapper();
    final JWKSet jwks =
            new JWKSet(
                    new ECKeyGenerator(Curve.P_256)
                            .keyID("es")
                            .algorithm(new Algorithm("ES256"))
                            .generate());

    final Authorize sut =
            new Authorize(
                    clientStore,
                    new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                    scopeAudienceMapper,
                    new InMemoryAccessTokenService(new InMemoryAccessTokenStore()),
                    new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks), null),
                    new IDTokenValidator(config, jwks),
                    config);

    public AuthorizeTest_ValidationError() throws JOSEException {
        clientStore.save(client);
        clientStore.save(noGrantTypesClient);
        clientStore.save(authorizationCodeClient);
        clientStore.save(noResponseTypesClient);
    }

    @Test
    void responseTypeIsNull() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .state("xyz")
                        .uiLocales("en ja")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage().errorType,
                AuthorizationErrorTypeWithoutRedirect.invalid_response_type);
        assertEquals(List.of("en", "ja"), response.errorPage().uiLocales);
        assertEquals(response.errorDescription, "response_type parse error");
    }

    @Test
    void illegalResponseType() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .clientId(client.clientId)
                        .responseType("illegal")
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage().errorType,
                AuthorizationErrorTypeWithoutRedirect.invalid_response_type);
        assertEquals(response.errorDescription, "response_type parse error");
    }

    @Test
    void illegalDisplay() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .display("invalid")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("invalid_request", queryMap.get("error"));
        assertEquals(response.errorDescription, "display parse error");
    }

    @Test
    void illegalIdTokenHint() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .display("page")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .idTokenHint("invalid")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("invalid_request", queryMap.get("error"));
        assertEquals(response.errorDescription, "invalid id_token_hint");
    }

    @Test
    void idTokenHintAndAuthenticatedUserUnmatched() {
        // setup
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
                                        "unmatched"));
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .display("page")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .idTokenHint(jws.serialize())
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("login_required", queryMap.get("error"));
        assertEquals(
                response.errorDescription,
                "id_token_hint subject and authenticatedUser subject unmatched");
    }

    @Test
    void clientIdIsNull() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage().errorType,
                AuthorizationErrorTypeWithoutRedirect.client_id_required);
        assertEquals(response.errorDescription, "client_id required");
    }

    @Test
    void clientNotExist() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .clientId("unknown")
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage().errorType,
                AuthorizationErrorTypeWithoutRedirect.client_not_found);
        assertEquals(response.errorDescription, "client not found");
    }

    @Test
    void unauthorizedRedirectUri() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .clientId(client.clientId)
                        .redirectUri("http://not.authorized.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage().errorType,
                AuthorizationErrorTypeWithoutRedirect.redirect_uri_not_allowed);
        assertEquals(response.errorDescription, "client doesn't allow redirect_uri");
    }

    @Test
    void noRedirectUri() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .clientId(client.clientId)
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage().errorType,
                AuthorizationErrorTypeWithoutRedirect.invalid_redirect_uri);
        assertEquals(response.errorDescription, "redirect_uri required");
    }

    @Test
    void scopeUnauthorizedForClient() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("invalid")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("invalid"))
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("invalid_scope", queryMap.get("error"));
        assertEquals(response.errorDescription, "client doesn't support enough scope");
    }

    @Test
    void grantTypeNotClientSupported() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .clientId(noGrantTypesClient.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .consentedScope(Set.of("rs:scope1"))
                        .authenticatedUserSubject("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("unauthorized_client", queryMap.get("error"));
        assertEquals(
                response.errorDescription,
                "response_type is code but client doesn't support authorization_code grant_type");
    }

    @Test
    void responseTypeIsCodeButClientNotSupportIt() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .clientId(noResponseTypesClient.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .consentedScope(Set.of("rs:scope1"))
                        .authenticatedUserSubject("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("unsupported_response_type", queryMap.get("error"));
        assertEquals(response.errorDescription, "client doesn't support response_type");
    }

    @Test
    void responseTypeIsTokenButClientNotSupportIt() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("token")
                        .clientId(noResponseTypesClient.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .consentedScope(Set.of("rs:scope1"))
                        .authenticatedUserSubject("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("unsupported_response_type", queryMap.get("error"));
        assertEquals(response.errorDescription, "client doesn't support response_type");
    }

    @Test
    void invalidMaxAge() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("openid")
                        .maxAge("invalid")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("openid"))
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("invalid_request", queryMap.get("error"));
        assertEquals(response.errorDescription, "max_age is not number");
    }

    @Test
    void illegalPrompt() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .prompt("illegal")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("invalid_request", queryMap.get("error"));
        assertEquals(response.errorDescription, "prompt parse error");
    }

    @Test
    void promptIsNoneButUserNotAuthenticated() {

        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("openid")
                        .prompt("none")
                        .consentedScope(Set.of())
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("login_required", queryMap.get("error"));
        assertEquals(response.errorDescription, "prompt is none but user not authenticated");
    }

    @Test
    void promptIsNoneButUserConsented() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("openid")
                        .prompt("none")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of())
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("consent_required", queryMap.get("error"));
        assertEquals(
                response.errorDescription, "prompt is none but user doesn't consent enough scope");
    }

    @Test
    void promptIsNoneAndOther() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("openid")
                        .prompt("none login")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of())
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("invalid_request", queryMap.get("error"));
        assertEquals(response.errorDescription, "prompt contains none and another");
    }

    @Test
    void authenticationTimeOverMaxAgeAndPromptIsNone() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond() - 11)
                        .maxAge("10")
                        .prompt("none")
                        .redirectUri("http://rp1.example.com")
                        .scope("openid")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("openid"))
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("login_required", queryMap.get("error"));
        assertEquals(response.errorDescription, "prompt is none but authTime over");
    }

    @Test
    void specifyRequestParameter() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .maxAge("10")
                        .redirectUri("http://rp1.example.com")
                        .scope("openid")
                        .prompt("none login")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of())
                        .state("xyz")
                        .request("request")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("request_not_supported", queryMap.get("error"));
        assertEquals(response.errorDescription, "request not supported");
    }

    @Test
    void specifyRequestUriParameter() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .maxAge("10")
                        .redirectUri("http://rp1.example.com")
                        .scope("openid")
                        .prompt("none")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of())
                        .state("xyz")
                        .requestUri("request uri")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("request_uri_not_supported", queryMap.get("error"));
        assertEquals(response.errorDescription, "request_uri not supported");
    }

    @Test
    void specifyRegistrationParameter() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .maxAge("10")
                        .redirectUri("http://rp1.example.com")
                        .scope("openid")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of())
                        .state("xyz")
                        .registration("registration")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("registration_not_supported", queryMap.get("error"));
        assertEquals(response.errorDescription, "registration not supported");
    }

    @Test
    void responseModeIsQueryButResponseTypeIsCodeAndToken() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code token")
                        .responseMode("query")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .maxAge("10")
                        .redirectUri("http://rp1.example.com")
                        .scope("openid")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("openid"))
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage().errorType,
                AuthorizationErrorTypeWithoutRedirect.invalid_response_mode);
        assertEquals(response.errorDescription, "response_mode parse error");
    }

    @Test
    void unsupportedResponseMode() {
        var config =
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
                        Set.of(GrantType.authorization_code),
                        Set.of(Set.of(ResponseType.code)),
                        Set.of(ResponseMode.query),
                        Set.of(),
                        List.of("acr"),
                        Duration.ofSeconds(3600),
                        Duration.ofSeconds(600),
                        Duration.ofSeconds(604800),
                        Duration.ofSeconds(3600));
        final Authorize sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()),
                        new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks), null),
                        new IDTokenValidator(config, jwks),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .authTime(Instant.now().getEpochSecond())
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .responseMode("fragment")
                        .authenticatedUserSubject("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage().errorType,
                AuthorizationErrorTypeWithoutRedirect.unsupported_response_mode);
        assertEquals(response.errorDescription, "azidp doesn't support response_mode");
    }

    @Test
    void unsupportedResponseType() {
        var config =
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
                        Set.of(GrantType.authorization_code),
                        Set.of(Set.of(ResponseType.code)),
                        Set.of(ResponseMode.query),
                        Set.of(),
                        List.of("acr"),
                        Duration.ofSeconds(3600),
                        Duration.ofSeconds(600),
                        Duration.ofSeconds(604800),
                        Duration.ofSeconds(3600));
        final Authorize sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()),
                        new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks), null),
                        new IDTokenValidator(config, jwks),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token")
                        .authTime(Instant.now().getEpochSecond())
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .consentedScope(Set.of("rs:scope1"))
                        .responseMode("query")
                        .authenticatedUserSubject("username")
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage().errorType,
                AuthorizationErrorTypeWithoutRedirect.unsupported_response_type);
        assertEquals(response.errorDescription, "azidp doesn't support response_type");
    }

    @Test
    void responseTypeIsTokenButNotSupportImplicit() {
        // setup
        var config =
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
                        Set.of(GrantType.authorization_code),
                        Set.of(Set.of(ResponseType.code), Set.of(ResponseType.token)),
                        Set.of(ResponseMode.query, ResponseMode.fragment),
                        Set.of(),
                        List.of("acr"),
                        Duration.ofSeconds(3600),
                        Duration.ofSeconds(600),
                        Duration.ofSeconds(604800),
                        Duration.ofSeconds(3600));
        final Authorize sut =
                new Authorize(
                        clientStore,
                        new InMemoryAuthorizationCodeService(new InMemoryAuthorizationCodeStore()),
                        scopeAudienceMapper,
                        new InMemoryAccessTokenService(new InMemoryAccessTokenStore()),
                        new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks), null),
                        new IDTokenValidator(config, jwks),
                        config);

        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token")
                        .clientId(authorizationCodeClient.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("unauthorized_client", queryMap.get("error"));
        assertEquals(
                response.errorDescription,
                "response_type is token or id_token but client doesn't support implicit"
                        + " grant_type");
    }

    @Test
    void oidcImplicitButNoNonce() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("id_token")
                        .authTime(Instant.now().getEpochSecond())
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .responseMode("fragment")
                        .authenticatedUserSubject("username")
                        .state("xyz")
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("invalid_request", queryMap.get("error"));
        assertEquals(response.errorDescription, "response_type is id_token but nonce not found");
    }

    @Test
    void codeChallengeMethodWithoutCodeChallenge() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .codeChallengeMethod("PLAIN")
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("invalid_request", queryMap.get("error"));
        assertEquals(
                response.errorDescription, "code_challenge_method specified but no code_challenge");
    }

    @Test
    void illegalCodeChallengeMethod() {
        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .codeChallenge("xyz")
                        .codeChallengeMethod("illegal")
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1", "rs:scope2"))
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("invalid_request", queryMap.get("error"));
        assertEquals(response.errorDescription, "code_challenge_method parse error");
    }

    @Test
    void responseTypeIsIdTokenButNoOpenIdScope() {

        // setup
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("token")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond())
                        .redirectUri("http://rp1.example.com")
                        .responseType("id_token")
                        .scope("rs:scope1")
                        .nonce("xyz")
                        .authenticatedUserSubject("username")
                        .consentedScope(Set.of("rs:scope1"))
                        .build();

        // exercise
        var response = sut.authorize(authorizationRequest);

        // verify
        assertEquals(response.next, NextAction.redirect);
        var location = response.redirect().createRedirectTo();
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getFragment().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("invalid_scope", queryMap.get("error"));
        assertEquals(
                response.errorDescription,
                "authorization request contains id_token response_type but no openid scope");
    }
}
