package org.azidp4j.springsecuritysample.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.Map;
import org.azidp4j.springsecuritysample.authentication.AcrValue;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {
            "server.port=8082",
            "endpoint=http://localhost:8082",
            "spring.main.allow-bean-definition-overriding=true"
        })
public class IntegrationTest_InMemory {

    @Test
    void exampleTest() throws IOException, ParseException, JOSEException {
        var endpoint = "http://localhost:8082";
        TestRestTemplate testRestTemplate =
                new TestRestTemplate(TestRestTemplate.HttpClientOption.ENABLE_COOKIES);
        TestRestTemplate apiRestTemplate = new TestRestTemplate();

        // token request by default client
        var tokenRequest = new LinkedMultiValueMap<>();
        tokenRequest.add("grant_type", "client_credentials");
        tokenRequest.add("scope", "default");
        var tokenRequestEntity =
                RequestEntity.post("/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .body(tokenRequest);
        var tokenResponse =
                apiRestTemplate
                        .withBasicAuth("default", "default")
                        .postForEntity(endpoint + "/token", tokenRequestEntity, Map.class);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        var defaultClientAccessToken = (String) tokenResponse.getBody().get("access_token");

        // client registration ========================
        var redirectUri = "https://example.com";
        var clientRegistrationResponse =
                ClientRegistrationScenario.test(
                        endpoint, apiRestTemplate, defaultClientAccessToken, redirectUri);
        var clientId = (String) clientRegistrationResponse.getBody().get("client_id");
        var clientSecret = (String) clientRegistrationResponse.getBody().get("client_secret");
        var configurationToken =
                (String) clientRegistrationResponse.getBody().get("registration_access_token");
        var configurationUri =
                (String) clientRegistrationResponse.getBody().get("registration_client_uri");

        // read client ========================
        {
            var clientReadEntity =
                    RequestEntity.get(configurationUri)
                            .accept(MediaType.APPLICATION_JSON)
                            .header("Authorization", "Bearer " + configurationToken)
                            .build();
            var clientReadResponse = apiRestTemplate.exchange(clientReadEntity, Map.class);
            assertThat(clientReadResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        String accessToken;
        String refreshToken;
        {
            // authorization request with login and consent ========================
            var authorizationCode =
                    AuthorizationRequestScenario.test(
                            endpoint, testRestTemplate, redirectUri, clientId);

            // token request by authorization code ========================
            var tokenResponseForAuthorizationCodeGrant =
                    TokenRequestByAuthorizationCode.test(
                            endpoint,
                            apiRestTemplate,
                            redirectUri,
                            clientId,
                            clientSecret,
                            authorizationCode);
            assertThat(tokenResponseForAuthorizationCodeGrant.getStatusCode())
                    .isEqualTo(HttpStatus.OK);
            accessToken =
                    (String) tokenResponseForAuthorizationCodeGrant.getBody().get("access_token");
            var idToken = (String) tokenResponseForAuthorizationCodeGrant.getBody().get("id_token");
            refreshToken =
                    (String) tokenResponseForAuthorizationCodeGrant.getBody().get("refresh_token");
            var jwks = JWKSet.load(new URL(endpoint + "/.well-known/jwks.json"));
            var parsedIdToken = JWSObject.parse(idToken);
            var jwk = jwks.getKeyByKeyId(parsedIdToken.getHeader().getKeyID());
            var verifier = new RSASSAVerifier((RSAKey) jwk);
            assertTrue(parsedIdToken.verify(verifier));
            // gender claims is from claims parameter
            assertEquals(parsedIdToken.getPayload().toJSONObject().get("gender"), "user1gender");
            // acr
            assertEquals(parsedIdToken.getPayload().toJSONObject().get("acr"), AcrValue.pwd.value);
        }

        // introspection ========================
        IntrospectionScenario.test(
                accessToken, apiRestTemplate, clientId, clientSecret, endpoint, true);

        // userinfo ========================
        UserInfoScenario.test(endpoint, apiRestTemplate, accessToken);

        // token refresh ========================
        var tokenRequestForRefresh = new LinkedMultiValueMap<>();
        tokenRequestForRefresh.add("grant_type", "refresh_token");
        tokenRequestForRefresh.add("refresh_token", refreshToken);
        tokenRequestForRefresh.add("scope", "scope1");
        var tokenRequestForRefreshEntity =
                RequestEntity.post("/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .body(tokenRequestForRefresh);
        var tokenResponseForRefreshGrant =
                apiRestTemplate
                        .withBasicAuth(clientId, clientSecret)
                        .postForEntity(
                                endpoint + "/token", tokenRequestForRefreshEntity, Map.class);
        assertThat(tokenResponseForRefreshGrant.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertNotNull(tokenResponseForRefreshGrant.getBody().get("access_token"));
        assertNotNull(tokenResponseForRefreshGrant.getBody().get("refresh_token"));

        // revoke ========================
        {
            var revocationRequest = new LinkedMultiValueMap<>();
            revocationRequest.add(
                    "token", (String) tokenResponseForRefreshGrant.getBody().get("access_token"));
            revocationRequest.add("token_type_hint", "access_token");
            var revocationRequestEntity =
                    RequestEntity.post("/revoke")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .accept(MediaType.APPLICATION_JSON)
                            .body(revocationRequest);
            var revocationResponse =
                    apiRestTemplate
                            .withBasicAuth(clientId, clientSecret)
                            .postForEntity(
                                    endpoint + "/revoke", revocationRequestEntity, Map.class);
            assertThat(revocationResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        // introspection
        {
            IntrospectionScenario.test(
                    (String) tokenResponseForRefreshGrant.getBody().get("access_token"),
                    apiRestTemplate,
                    clientId,
                    clientSecret,
                    endpoint,
                    false);
        }

        {
            // authorization request with login and consent ========================
            var authorizationCode =
                    AuthorizationRequestWithAcrValuesScenario.test(
                            endpoint, testRestTemplate, redirectUri, clientId);

            // token request by authorization code ========================
            var tokenResponseForAuthorizationCodeGrant =
                    TokenRequestByAuthorizationCode.test(
                            endpoint,
                            apiRestTemplate,
                            redirectUri,
                            clientId,
                            clientSecret,
                            authorizationCode);
            assertThat(tokenResponseForAuthorizationCodeGrant.getStatusCode())
                    .isEqualTo(HttpStatus.OK);
            accessToken =
                    (String) tokenResponseForAuthorizationCodeGrant.getBody().get("access_token");
            assertNotNull(accessToken);
            var idToken = (String) tokenResponseForAuthorizationCodeGrant.getBody().get("id_token");
            refreshToken =
                    (String) tokenResponseForAuthorizationCodeGrant.getBody().get("refresh_token");
            assertNotNull(refreshToken);
            var jwks = JWKSet.load(new URL(endpoint + "/.well-known/jwks.json"));
            var parsedIdToken = JWSObject.parse(idToken);
            var jwk = jwks.getKeyByKeyId(parsedIdToken.getHeader().getKeyID());
            var verifier = new RSASSAVerifier((RSAKey) jwk);
            assertTrue(parsedIdToken.verify(verifier));
            // gender claims is from claims parameter
            assertEquals(parsedIdToken.getPayload().toJSONObject().get("gender"), "user1gender");
            // acr
            assertEquals(
                    parsedIdToken.getPayload().toJSONObject().get("acr"),
                    AcrValue.self_reported.value);
        }

        {
            // authorization request with login and consent ========================
            var authorizationCode =
                    AuthorizationRequestWithAcrClaimsParameterScenario.test(
                            endpoint, testRestTemplate, redirectUri, clientId);

            // token request by authorization code ========================
            var tokenResponseForAuthorizationCodeGrant =
                    TokenRequestByAuthorizationCode.test(
                            endpoint,
                            apiRestTemplate,
                            redirectUri,
                            clientId,
                            clientSecret,
                            authorizationCode);
            assertThat(tokenResponseForAuthorizationCodeGrant.getStatusCode())
                    .isEqualTo(HttpStatus.OK);
            accessToken =
                    (String) tokenResponseForAuthorizationCodeGrant.getBody().get("access_token");
            assertNotNull(accessToken);
            var idToken = (String) tokenResponseForAuthorizationCodeGrant.getBody().get("id_token");
            refreshToken =
                    (String) tokenResponseForAuthorizationCodeGrant.getBody().get("refresh_token");
            assertNotNull(refreshToken);
            var jwks = JWKSet.load(new URL(endpoint + "/.well-known/jwks.json"));
            var parsedIdToken = JWSObject.parse(idToken);
            var jwk = jwks.getKeyByKeyId(parsedIdToken.getHeader().getKeyID());
            var verifier = new RSASSAVerifier((RSAKey) jwk);
            assertTrue(parsedIdToken.verify(verifier));
            // gender claims is from claims parameter
            assertEquals(parsedIdToken.getPayload().toJSONObject().get("gender"), "user1gender");
            // acr
            assertEquals(
                    parsedIdToken.getPayload().toJSONObject().get("acr"),
                    AcrValue.self_reported.value);
        }

        // delete client ========================
        var clientDeleteEntity =
                RequestEntity.delete(configurationUri)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + configurationToken)
                        .build();
        var clientDeleteResponse = apiRestTemplate.exchange(clientDeleteEntity, Map.class);
        assertThat(clientDeleteResponse.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }
}
