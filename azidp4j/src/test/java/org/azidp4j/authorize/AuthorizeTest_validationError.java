package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.jwk.JWKSet;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.Fixtures;
import org.azidp4j.client.*;
import org.azidp4j.scope.SampleScopeAudienceMapper;
import org.azidp4j.token.TokenEndpointAuthMethod;
import org.azidp4j.token.accesstoken.InMemoryAccessTokenStore;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.junit.jupiter.api.Test;

class AuthorizeTest_validationError {

    ClientStore clientStore = new InMemoryClientStore();
    Client client =
            new Client(
                    "client1",
                    "clientSecret",
                    Set.of("http://rp1.example.com", "http://rp2.example.com"),
                    Set.of(GrantType.authorization_code, GrantType.implicit),
                    Set.of(ResponseType.code, ResponseType.token),
                    "scope1 scope2 openid",
                    TokenEndpointAuthMethod.client_secret_basic,
                    Set.of(SigningAlgorithm.ES256));
    Client noGrantTypesClient =
            new Client(
                    "noGrantTypesClient",
                    "clientSecret",
                    Set.of("http://rp1.example.com"),
                    Set.of(),
                    Set.of(ResponseType.code),
                    "scope1 scope2",
                    TokenEndpointAuthMethod.client_secret_basic,
                    Set.of(SigningAlgorithm.ES256));

    Client noResponseTypesClient =
            new Client(
                    "noResponseTypesClient",
                    "clientSecret",
                    Set.of("http://rp1.example.com"),
                    Set.of(GrantType.authorization_code, GrantType.implicit),
                    Set.of(),
                    "scope1 scope2",
                    TokenEndpointAuthMethod.client_secret_basic,
                    Set.of(SigningAlgorithm.ES256));
    AzIdPConfig config = Fixtures.azIdPConfig("kid");
    Authorize sut =
            new Authorize(
                    clientStore,
                    new InMemoryAuthorizationCodeStore(),
                    new InMemoryAccessTokenStore(),
                    new SampleScopeAudienceMapper(),
                    new IDTokenIssuer(config, new JWKSet()),
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
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("scope1")
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.status, 400);
    }

    @Test
    void illegalResponseType() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .clientId(client.clientId)
                        .responseType("illegal")
                        .redirectUri("http://rp1.example.com")
                        .scope("scope1")
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.status, 400);
    }

    @Test
    void clientIdIsNull() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .redirectUri("http://rp1.example.com")
                        .scope("scope1")
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.status, 400);
    }

    @Test
    void clientNotExist() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId("unknown")
                        .redirectUri("http://rp1.example.com")
                        .scope("scope1")
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.status, 400);
    }

    @Test
    void unauthorizedRedirectUri() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .redirectUri("http://not.authorized.example.com")
                        .scope("scope1")
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.status, 400);
    }

    @Test
    void noRedirectUri() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .scope("scope1")
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.status, 400);
    }

    @Test
    void scopeUnauthorizedForClient() {
        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .responseType("code")
                        .clientId(client.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("invalid")
                        .authenticatedUserId("username")
                        .consentedScope(Set.of("invalid"))
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.status, 302);
        var location = URI.create(response.headers().get("Location"));
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
                        .responseType("code")
                        .clientId(noGrantTypesClient.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("scope1")
                        .consentedScope(Set.of("scope1"))
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.status, 302);
        var location = URI.create(response.headers().get("Location"));
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
                        .responseType("code")
                        .clientId(noResponseTypesClient.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("scope1")
                        .consentedScope(Set.of("scope1"))
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.status, 302);
        var location = URI.create(response.headers().get("Location"));
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
                        .responseType("code")
                        .clientId(noResponseTypesClient.clientId)
                        .redirectUri("http://rp1.example.com")
                        .scope("scope1")
                        .consentedScope(Set.of("scope1"))
                        .authenticatedUserId("username")
                        .state("xyz")
                        .build();
        var response = sut.authorize(authorizationRequest);
        assertEquals(response.status, 302);
        var location = URI.create(response.headers().get("Location"));
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
        assertEquals(response.status, 302);
        var location = URI.create(response.headers().get("Location"));
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
        assertEquals(response.status, 302);
        var location = URI.create(response.headers().get("Location"));
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
        assertEquals(response.status, 302);
        var location = URI.create(response.headers().get("Location"));
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
        assertEquals(response.status, 302);
        var location = URI.create(response.headers().get("Location"));
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
        assertEquals(response.status, 302);
        var location = URI.create(response.headers().get("Location"));
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
        assertEquals(response.status, 302);
        var location = URI.create(response.headers().get("Location"));
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
        assertEquals(response.status, 302);
        var location = URI.create(response.headers().get("Location"));
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
        assertEquals(response.status, 302);
        var location = URI.create(response.headers().get("Location"));
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
        assertEquals(response.status, 400);
    }
}
