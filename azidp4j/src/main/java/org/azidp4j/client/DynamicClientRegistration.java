package org.azidp4j.client;

import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.request.ClientRequest;
import org.azidp4j.client.request.ClientRequestParser;
import org.azidp4j.client.request.InternalClientRequest;
import org.azidp4j.client.response.ClientDeleteResponse;
import org.azidp4j.client.response.ClientReadResponse;
import org.azidp4j.client.response.ClientRegistrationResponse;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.util.MapUtil;

public class DynamicClientRegistration {

    private final AzIdPConfig config;
    private final ClientStore clientStore;
    private final AccessTokenService accessTokenService;
    private final InternalClientValidator clientValidator;
    private final ClientValidator customizableClientValidator;
    private final ClientRequestParser clientRequestParser = new ClientRequestParser();
    private final Function<String, String> clientConfigurationEndpointIssuer;

    public DynamicClientRegistration(
            AzIdPConfig config,
            ClientStore clientStore,
            ClientValidator customizableClientValidator,
            AccessTokenService accessTokenService,
            Function<String, String> clientConfigurationEndpointIssuer) {
        this.config = config;
        this.clientStore = clientStore;
        this.clientValidator = new InternalClientValidator(config);
        this.customizableClientValidator =
                customizableClientValidator != null ? customizableClientValidator : client -> {};
        this.accessTokenService = accessTokenService;
        if (clientConfigurationEndpointIssuer == null) {
            this.clientConfigurationEndpointIssuer = (clientId) -> null;
        } else {
            this.clientConfigurationEndpointIssuer = clientConfigurationEndpointIssuer;
        }
    }

    public ClientRegistrationResponse register(ClientRequest req) {
        InternalClientRequest request;
        try {
            request = clientRequestParser.parse(req);
        } catch (IllegalArgumentException e) {
            return new ClientRegistrationResponse(400, Map.of("error", "invalid_client_metadata"));
        }
        Set<GrantType> grantTypes = new HashSet<>();
        if (request.grantTypes == null) {
            // default
            grantTypes.add(GrantType.authorization_code);
        } else {
            for (String g : request.grantTypes) {
                if (g == null) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_client_metadata"));
                }
                try {
                    var grantType = GrantType.of(g);
                    grantTypes.add(grantType);
                } catch (IllegalArgumentException e) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_client_metadata"));
                }
            }
        }

        Set<Set<ResponseType>> responseTypes = new HashSet<>();
        if (request.responseTypes == null) {
            // default
            responseTypes.add(Set.of(ResponseType.code));
        } else {
            for (String r : request.responseTypes) {
                try {
                    var responseType = ResponseType.parse(r);
                    responseTypes.add(responseType);
                } catch (IllegalArgumentException e) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_client_metadata"));
                }
            }
        }

        var applicationType = ApplicationType.WEB;
        if (request.applicationType != null) {
            try {
                applicationType = ApplicationType.of(request.applicationType);
            } catch (IllegalArgumentException e) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_client_metadata"));
            }
        }

        var tokenEndpointAuthMethod = TokenEndpointAuthMethod.client_secret_basic;
        if (request.tokenEndpointAuthMethod != null) {
            try {
                var tam = TokenEndpointAuthMethod.of(request.tokenEndpointAuthMethod);
                tokenEndpointAuthMethod = tam;
            } catch (IllegalArgumentException e) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_client_metadata"));
            }
        }
        if (!config.tokenEndpointAuthMethodsSupported.contains(tokenEndpointAuthMethod)) {
            return new ClientRegistrationResponse(400, Map.of("error", "invalid_client_metadata"));
        }
        if (tokenEndpointAuthMethod == TokenEndpointAuthMethod.private_key_jwt
                || tokenEndpointAuthMethod == TokenEndpointAuthMethod.client_secret_jwt) {
            if (request.tokenEndpointAuthSigningAlg == null) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_client_metadata"));
            } else {
                if (!config.tokenEndpointAuthSigningAlgValuesSupported.contains(
                        request.tokenEndpointAuthSigningAlg)) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_client_metadata"));
                }
            }
        }

        var idTokenSignedResponseAlg = SigningAlgorithm.RS256;
        if (request.idTokenSignedResponseAlg != null) {
            try {
                idTokenSignedResponseAlg = SigningAlgorithm.of(request.idTokenSignedResponseAlg);
            } catch (IllegalArgumentException e) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_client_metadata"));
            }
        }

        var client =
                new Client(
                        UUID.randomUUID().toString(),
                        tokenEndpointAuthMethod != TokenEndpointAuthMethod.none
                                ? UUID.randomUUID().toString()
                                : null,
                        request.redirectUris != null ? request.redirectUris : Set.of(),
                        responseTypes,
                        applicationType,
                        grantTypes,
                        request.clientName,
                        request.clientUri,
                        request.logoUri,
                        request.scope,
                        request.contacts,
                        request.tosUri,
                        request.policyUri,
                        request.jwksUri,
                        request.jwks,
                        request.softwareId,
                        request.softwareVersion,
                        tokenEndpointAuthMethod,
                        request.tokenEndpointAuthSigningAlg,
                        idTokenSignedResponseAlg,
                        request.defaultMaxAge,
                        request.requireAuthTime != null ? request.requireAuthTime : false,
                        request.initiateLoginUri);
        try {
            clientValidator.validate(client);
            customizableClientValidator.validate(client);
        } catch (IllegalArgumentException e) {
            return new ClientRegistrationResponse(400, Map.of("error", "invalid_client_metadata"));
        }
        clientStore.save(client);
        var at =
                accessTokenService.issue(
                        client.clientId,
                        "configure",
                        client.clientId,
                        Instant.now().getEpochSecond() + config.accessTokenExpiration.toSeconds(),
                        Instant.now().getEpochSecond(),
                        Set.of(config.issuer),
                        null);
        var clientConfigurationEndpoint = clientConfigurationEndpointIssuer.apply(client.clientId);
        var res = response(client);
        Optional.ofNullable(clientConfigurationEndpoint)
                .ifPresent(v -> res.put("registration_client_uri", v));
        Optional.ofNullable(clientConfigurationEndpoint)
                .ifPresent(v -> res.put("registration_access_token", at.getToken()));
        return new ClientRegistrationResponse(201, res);
    }

    public ClientDeleteResponse delete(String clientId) {
        clientStore.remove(clientId);
        return new ClientDeleteResponse(204, null);
    }

    public ClientReadResponse read(String clientId) {
        var clientOpt = clientStore.find(clientId);
        if (clientOpt.isEmpty()) {
            return new ClientReadResponse(404, null);
        }
        var client = clientOpt.get();
        return new ClientReadResponse(200, response(client));
    }

    private Map<String, Object> response(Client client) {
        var res =
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
                        client.responseTypes.stream()
                                .map(
                                        r -> {
                                            var joiner = new StringJoiner(" ");
                                            r.forEach(v -> joiner.add(v.name()));
                                            return joiner.toString();
                                        })
                                .collect(Collectors.toSet()),
                        "application_type",
                        client.applicationType.name().toLowerCase(),
                        "client_uri",
                        client.clientUri,
                        "logo_uri",
                        client.logoUri,
                        "scope",
                        client.scope,
                        "contacts",
                        client.contacts,
                        "jwks_uri",
                        client.jwksUri,
                        "jwks",
                        client.jwks != null ? client.jwks.toJSONObject() : null,
                        "software_id",
                        client.softwareId,
                        "software_version",
                        client.softwareVersion,
                        "token_endpoint_auth_method",
                        client.tokenEndpointAuthMethod.name(),
                        "token_endpoint_auth_signing_alg",
                        client.tokenEndpointAuthSigningAlg,
                        "id_token_signed_response_alg",
                        client.idTokenSignedResponseAlg.name(),
                        "default_max_age",
                        client.defaultMaxAge,
                        "require_auth_time",
                        client.requireAuthTime,
                        "initiate_login_uri",
                        client.initiateLoginUri);
        Optional.ofNullable(client.clientName).ifPresent(v -> res.putAll(v.toMap()));
        Optional.ofNullable(client.tosUri).ifPresent(v -> res.putAll(v.toMap()));
        Optional.ofNullable(client.policyUri).ifPresent(v -> res.putAll(v.toMap()));
        return res;
    }
}
