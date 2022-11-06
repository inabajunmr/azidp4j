package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.jwk.JWKSet;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
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
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.token.SampleIdTokenKidSupplier;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.junit.jupiter.api.Test;

class AuthorizeTest_validationError {

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

    public AuthorizeTest_validationError() {
        clientStore.save(client);
        clientStore.save(noGrantTypesClient);
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
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage.errorType,
                AuthorizationErrorTypeWithoutRedirect.invalid_response_type);
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
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage.errorType,
                AuthorizationErrorTypeWithoutRedirect.invalid_response_type);
    }

    @Test
    void clientIdIsNull() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage.errorType,
                AuthorizationErrorTypeWithoutRedirect.client_id_required);
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
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage.errorType,
                AuthorizationErrorTypeWithoutRedirect.client_not_found);
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
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage.errorType,
                AuthorizationErrorTypeWithoutRedirect.redirect_uri_not_allowed);
    }

    @Test
    void noRedirectUri() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .clientId(client.clientId)
                        .scope("rs:scope1")
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage.errorType,
                AuthorizationErrorTypeWithoutRedirect.invalid_redirect_uri);
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
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("invalid"))
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = URI.create(response.redirect.redirectTo);
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("invalid_scope", queryMap.get("error"));
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
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = URI.create(response.redirect.redirectTo);
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("unauthorized_client", queryMap.get("error"));
    }

    @Test
    void responseTypeNotSupportedClient_AuthorizationCodeGrant() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .clientId(noResponseTypesClient.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .consentedScope(Set.of("rs:scope1"))
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = URI.create(response.redirect.redirectTo);
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("unsupported_response_type", queryMap.get("error"));
    }

    @Test
    void responseTypeNotSupportedClient_ImplicitGrant() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .authTime(Instant.now().getEpochSecond())
                        .responseType("code")
                        .clientId(noResponseTypesClient.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .consentedScope(Set.of("rs:scope1"))
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = URI.create(response.redirect.redirectTo);
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("unsupported_response_type", queryMap.get("error"));
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
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("openid"))
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = URI.create(response.redirect.redirectTo);
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("invalid_request", queryMap.get("error"));
    }

    @Test
    void promptIsNoneButUserNotAuthenticated() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("openid")
                        .maxAge("invalid")
                        .prompt("none")
                        .consentedScope(Set.of())
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = URI.create(response.redirect.redirectTo);
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("login_required", queryMap.get("error"));
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
                        .maxAge("invalid")
                        .prompt("none")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of())
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = URI.create(response.redirect.redirectTo);
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("consent_required", queryMap.get("error"));
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
                        .maxAge("invalid")
                        .prompt("none login")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of())
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = URI.create(response.redirect.redirectTo);
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("invalid_request", queryMap.get("error"));
    }

    @Test
    void authenticationTimeOverMaxAge() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .authTime(Instant.now().getEpochSecond() - 11)
                        .maxAge("10")
                        .redirectUri("http://rp1.example.com")
                        .scope("openid")
                        .maxAge("invalid")
                        .prompt("none login")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of())
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = URI.create(response.redirect.redirectTo);
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("invalid_request", queryMap.get("error"));
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
                        .maxAge("invalid")
                        .prompt("none login")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of())
                        .state("xyz")
                        .request("request")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = URI.create(response.redirect.redirectTo);
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("request_not_supported", queryMap.get("error"));
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
                        .maxAge("invalid")
                        .prompt("none login")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of())
                        .state("xyz")
                        .requestUri("request uri")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = URI.create(response.redirect.redirectTo);
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("request_uri_not_supported", queryMap.get("error"));
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
                        .authenticatedUserId("username")
                        .consentedScope(Set.of())
                        .state("xyz")
                        .registration("registration")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.redirect);
        var location = URI.create(response.redirect.redirectTo);
        assertEquals("rp1.example.com", location.getHost());
        var queryMap =
                Arrays.stream(location.getQuery().split("&"))
                        .collect(Collectors.toMap(kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
        assertEquals("xyz", queryMap.get("state"));
        assertEquals("registration_not_supported", queryMap.get("error"));
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
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("openid"))
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage.errorType,
                AuthorizationErrorTypeWithoutRedirect.invalid_response_mode);
    }

    @Test
    void unsupportedResponseMode() {
        var config =
                new AzIdPConfig(
                        "http://localhost:8080",
                        Set.of("openid", "rs:scope1", "rs:scope2", "rs:scope3", "default"),
                        Set.of("openid", "rs:scope1"),
                        Set.of(GrantType.authorization_code),
                        Set.of(Set.of(ResponseType.code)),
                        Set.of(ResponseMode.query),
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
                        new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks)),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .authTime(Instant.now().getEpochSecond())
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .responseMode("fragment")
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage.errorType,
                AuthorizationErrorTypeWithoutRedirect.unsupported_response_mode);
    }

    @Test
    void unsupportedResponseType() {
        var config =
                new AzIdPConfig(
                        "http://localhost:8080",
                        Set.of("openid", "rs:scope1", "rs:scope2", "rs:scope3", "default"),
                        Set.of("openid", "rs:scope1"),
                        Set.of(GrantType.authorization_code),
                        Set.of(Set.of(ResponseType.code)),
                        Set.of(ResponseMode.query),
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
                        new IDTokenIssuer(config, jwks, new SampleIdTokenKidSupplier(jwks)),
                        config);
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .authTime(Instant.now().getEpochSecond())
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("rs:scope1")
                        .responseMode("fragment")
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.next, NextAction.errorPage);
        assertEquals(
                response.errorPage.errorType,
                AuthorizationErrorTypeWithoutRedirect.unsupported_response_mode);
    }
}
