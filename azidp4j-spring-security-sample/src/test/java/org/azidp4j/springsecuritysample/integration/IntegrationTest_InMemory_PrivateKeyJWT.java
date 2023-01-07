package org.azidp4j.springsecuritysample.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.Map;
import java.util.Set;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.TokenEndpointAuthMethod;
import org.azidp4j.springsecuritysample.authentication.AcrValue;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {
            "server.port=8083",
            "endpoint=http://localhost:8083",
            "spring.main.allow-bean-definition-overriding=true"
        })
public class IntegrationTest_InMemory_PrivateKeyJWT {

    @Test
    void exampleTest() throws IOException, ParseException, JOSEException {
        var endpoint = "http://localhost:8083";
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

        var clientRegistrationRequest =
                Map.of(
                        "redirect_uris",
                        Set.of(redirectUri),
                        "grant_types",
                        Set.of(
                                GrantType.authorization_code.name(),
                                GrantType.implicit.name(),
                                GrantType.password.name(),
                                GrantType.refresh_token.name()),
                        "response_types",
                        Set.of(ResponseType.code.name(), ResponseType.token.name()),
                        "scope",
                        "scope1 scope2 openid profile email address phone",
                        "id_token_signed_response_alg",
                        "RS256",
                        "token_endpoint_auth_method",
                        TokenEndpointAuthMethod.private_key_jwt.name(),
                        "token_endpoint_auth_signing_alg",
                        "ES256",
                        "jwks",
                        ClientJWKs.JWKS.toPublicJWKSet().toJSONObject());
        var clientRegistrationEntity =
                RequestEntity.post("/client")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + defaultClientAccessToken)
                        .body(clientRegistrationRequest);
        var clientRegistrationResponse =
                testRestTemplate.postForEntity(
                        endpoint + "/client", clientRegistrationEntity, Map.class);
        assertThat(clientRegistrationResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        var clientId = (String) clientRegistrationResponse.getBody().get("client_id");
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

        {
            // authorization request with login and consent ========================
            var authorizationCode =
                    AuthorizationRequestScenario.test(
                            endpoint, testRestTemplate, redirectUri, clientId);

            // token request by authorization code ========================
            MultiValueMap<String, String> tokenRequestForAuthorizationCodeGrant =
                    new LinkedMultiValueMap<>();
            tokenRequestForAuthorizationCodeGrant.add("grant_type", "authorization_code");
            tokenRequestForAuthorizationCodeGrant.add("code", authorizationCode);
            tokenRequestForAuthorizationCodeGrant.add("redirect_uri", redirectUri);
            tokenRequestForAuthorizationCodeGrant.add("client_id", clientId);
            // private_key_jwt
            var assertion =
                    ClientAuthenticationJWTAssertionGenerator.getJwsObject(
                            endpoint + "/token", clientId);
            tokenRequestForAuthorizationCodeGrant.add("client_assertion", assertion.serialize());
            tokenRequestForAuthorizationCodeGrant.add(
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");

            var tokenRequestForAuthorizationCodeGrantEntity =
                    RequestEntity.post("/token")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .accept(MediaType.APPLICATION_JSON)
                            .body(tokenRequestForAuthorizationCodeGrant);
            var tokenResponseForAuthorizationCodeGrant =
                    testRestTemplate.postForEntity(
                            endpoint + "/token",
                            tokenRequestForAuthorizationCodeGrantEntity,
                            Map.class);
            assertThat(tokenResponseForAuthorizationCodeGrant.getStatusCode())
                    .isEqualTo(HttpStatus.OK);
            var idToken = (String) tokenResponseForAuthorizationCodeGrant.getBody().get("id_token");
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
    }
}
