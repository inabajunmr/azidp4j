package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.client.Client;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.InMemoryClientStore;
import org.junit.jupiter.api.Test;

class AuthorizeTest {

    @Test
    void validationError() {
        var clientStore = new InMemoryClientStore();
        var client =
                new Client(
                        "clientId",
                        "clientSecret",
                        Set.of("http://example.com"),
                        Set.of(GrantType.authorization_code),
                        Set.of(ResponseType.code),
                        "scope1 scope2");
        clientStore.save(client);
        var sut = new Authorize(clientStore, new InMemoryAuthorizationCodeStore());
        // response type is null
        {
            var authorizationRequest =
                    AuthorizationRequest.builder()
                            .clientId(client.clientId)
                            .redirectUri("http://example.com")
                            .scope("scope1")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 400);
        }
        // illegal response type
        {
            var authorizationRequest =
                    AuthorizationRequest.builder()
                            .clientId(client.clientId)
                            .redirectUri("http://example.com")
                            .scope("scope1")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 400);
        }
        // client id is null
        {
            var authorizationRequest =
                    AuthorizationRequest.builder()
                            .responseType("code")
                            .redirectUri("http://example.com")
                            .scope("scope1")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 400);
        }
        // client not exist
        {
            var authorizationRequest =
                    AuthorizationRequest.builder()
                            .responseType("code")
                            .clientId("unknown")
                            .redirectUri("http://example.com")
                            .scope("scope1")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 400);
        }
        // unauthorized redirect uri
        {
            var authorizationRequest =
                    AuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://not.authorized.example.com")
                            .scope("scope1")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 400);
        }
        // unauthorized scope
        {
            var authorizationRequest =
                    AuthorizationRequest.builder()
                            .responseType("code")
                            .clientId(client.clientId)
                            .redirectUri("http://example.com")
                            .scope("invalid")
                            .sub("username")
                            .state("xyz")
                            .build();
            var response = sut.authorize(authorizationRequest);
            assertEquals(response.status, 302);
            var location = URI.create(response.headers("http://example.com").get("Location"));
            assertEquals("example.com", location.getHost());
            var queryMap =
                    Arrays.stream(location.getQuery().split("&"))
                            .collect(
                                    Collectors.toMap(
                                            kv -> kv.split("=")[0], kv -> kv.split("=")[1]));
            assertEquals("xyz", queryMap.get("state"));
            assertEquals("invalid_scope", queryMap.get("error"));
        }
        // TODO grant type
        // TODO response type
    }
}
