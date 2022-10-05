package org.azidp4j.client;

import com.nimbusds.jose.jwk.JWKSet;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.token.TokenEndpointAuthMethod;
import org.azidp4j.token.accesstoken.AccessTokenStore;
import org.azidp4j.token.accesstoken.InMemoryAccessToken;
import org.azidp4j.util.MapUtil;

public class DynamicClientRegistration {

    private final AzIdPConfig config;
    private final ClientStore clientStore;
    private final AccessTokenStore accessTokenStore;
    private final JWKSet jwkSet;

    public DynamicClientRegistration(
            AzIdPConfig config,
            ClientStore clientStore,
            AccessTokenStore accessTokenStore,
            JWKSet jwkSet) {
        this.config = config;
        this.clientStore = clientStore;
        this.accessTokenStore = accessTokenStore;
        this.jwkSet = jwkSet;
    }

    public ClientRegistrationResponse register(ClientRegistrationRequest request) {

        Set<GrantType> grantTypes = new HashSet<>();
        if (request.grantTypes == null) {
            // default
            grantTypes.add(GrantType.authorization_code);
        } else {
            for (String g : request.grantTypes) {
                var grantType = GrantType.of(g);
                if (grantType == null) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_grant_type"));
                }
                grantTypes.add(grantType);
            }
        }

        Set<ResponseType> responseTypes = new HashSet<>();
        if (request.responseTypes == null) {
            // default
            responseTypes.add(ResponseType.code);
        } else {
            for (String r : request.responseTypes) {
                var responseType = ResponseType.of(r);
                if (responseType == null) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_response_type"));
                }
                responseTypes.add(responseType);
            }
        }

        TokenEndpointAuthMethod tokenEndpointAuthMethod =
                TokenEndpointAuthMethod.client_secret_basic;
        if (request.tokenEndpointAuthMethod != null) {
            var tam = TokenEndpointAuthMethod.of(request.tokenEndpointAuthMethod);
            if (tam == null) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_token_endpoint_auth_method"));
            }
            tokenEndpointAuthMethod = tam;
        }

        var idTokenSignedResponseAlg = new HashSet<SigningAlgorithm>();
        if (request.idTokenSignedResponseAlg == null
                || request.idTokenSignedResponseAlg.isEmpty()) {
            idTokenSignedResponseAlg.add(SigningAlgorithm.ES256);
        } else {
            for (String r : request.idTokenSignedResponseAlg) {
                var alg = SigningAlgorithm.of(r);
                if (alg == null) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_response_type"));
                }
                idTokenSignedResponseAlg.add(alg);
            }
        }

        var client =
                new Client(
                        UUID.randomUUID().toString(),
                        tokenEndpointAuthMethod != TokenEndpointAuthMethod.none
                                ? UUID.randomUUID().toString()
                                : null,
                        request.redirectUris != null ? request.redirectUris : Set.of(),
                        grantTypes,
                        responseTypes,
                        request.scope,
                        tokenEndpointAuthMethod,
                        idTokenSignedResponseAlg);
        clientStore.save(client);
        var at =
                new InMemoryAccessToken(
                        UUID.randomUUID().toString(),
                        client.clientId,
                        "configure",
                        client.clientId,
                        Set.of(config.issuer),
                        Instant.now().getEpochSecond() + config.accessTokenExpirationSec);
        accessTokenStore.save(at);
        return new ClientRegistrationResponse(
                201,
                MapUtil.nullRemovedMap(
                        "client_id",
                        client.clientId,
                        "client_secret",
                        client.clientSecret,
                        "registration_access_token",
                        at.getToken(),
                        "registration_client_uri",
                        config.clientConfigurationEndpointPattern.replace(
                                "{CLIENT_ID}", client.clientId),
                        "redirect_uris",
                        client.redirectUris,
                        "grant_types",
                        client.grantTypes.stream().map(Enum::name).collect(Collectors.toSet()),
                        "response_types",
                        client.responseTypes.stream().map(Enum::name).collect(Collectors.toSet()),
                        "scope",
                        client.scope,
                        "token_endpoint_auth_method",
                        client.tokenEndpointAuthMethod.name(),
                        "id_token_signed_response_alg",
                        client.idTokenSignedResponseAlg.stream()
                                .map(Enum::name)
                                .collect(Collectors.toSet())));
    }

    public ClientRegistrationResponse configure(ClientConfigurationRequest request) {
        var client = clientStore.find(request.clientId);
        if (client == null) {
            throw new AssertionError();
        }
        var grantTypes = client.grantTypes;
        if (request.grantTypes != null) {
            grantTypes = new HashSet<>();
            for (String g : request.grantTypes) {
                var grantType = GrantType.of(g);
                if (grantType == null) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_grant_type"));
                }
                grantTypes.add(grantType);
            }
        }
        var scope = client.scope;
        if (request.scope != null) {
            scope = request.scope;
        }
        var redirectUris = client.redirectUris;
        if (request.redirectUris != null) {
            redirectUris = request.redirectUris;
        }
        var tokenEndpointAuthMethod = client.tokenEndpointAuthMethod;
        if (request.tokenEndpointAuthMethod != null) {
            var tam = TokenEndpointAuthMethod.of(request.tokenEndpointAuthMethod);
            if (tam == null) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_token_endpoint_auth_method"));
            }
            tokenEndpointAuthMethod = tam;
        }
        var responseTypes = client.responseTypes;
        if (request.responseTypes != null) {
            for (String r : request.responseTypes) {
                var responseType = ResponseType.of(r);
                if (responseType == null) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_response_type"));
                }
                responseTypes.add(responseType);
            }
        }
        var idTokenSignedResponseAlg = client.idTokenSignedResponseAlg;
        if (request.idTokenSignedResponseAlg != null
                && request.idTokenSignedResponseAlg.isEmpty()) {
            for (String r : request.idTokenSignedResponseAlg) {
                var alg = SigningAlgorithm.of(r);
                if (alg == null) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_response_type"));
                }
                idTokenSignedResponseAlg.add(alg);
            }
        }

        var updated =
                new Client(
                        client.clientId,
                        client.clientSecret,
                        redirectUris,
                        grantTypes,
                        responseTypes,
                        scope,
                        tokenEndpointAuthMethod,
                        idTokenSignedResponseAlg);
        clientStore.save(updated);
        return new ClientRegistrationResponse(
                200,
                MapUtil.nullRemovedMap(
                        "client_id",
                        updated.clientId,
                        "client_secret",
                        updated.clientSecret,
                        "redirect_uris",
                        updated.redirectUris,
                        "grant_types",
                        updated.grantTypes.stream().map(Enum::name).collect(Collectors.toSet()),
                        "response_types",
                        updated.responseTypes.stream().map(Enum::name).collect(Collectors.toSet()),
                        "scope",
                        updated.scope,
                        "token_endpoint_auth_method",
                        updated.tokenEndpointAuthMethod.name(),
                        "id_token_signed_response_alg",
                        client.idTokenSignedResponseAlg.stream()
                                .map(Enum::name)
                                .collect(Collectors.toSet())));
    }

    public ClientDeleteResponse delete(String clientId) {
        var client = clientStore.delete(clientId);
        return new ClientDeleteResponse(
                200,
                MapUtil.nullRemovedMap(
                        "client_id",
                        client.clientId,
                        "client_secret",
                        client.clientSecret,
                        "redirect_uris",
                        client.redirectUris,
                        "grant_types",
                        client.grantTypes.stream().map(Enum::name).collect(Collectors.toSet()),
                        "response_types",
                        client.responseTypes.stream().map(Enum::name).collect(Collectors.toSet()),
                        "scope",
                        client.scope,
                        "token_endpoint_auth_method",
                        client.tokenEndpointAuthMethod.name()));
    }
}
