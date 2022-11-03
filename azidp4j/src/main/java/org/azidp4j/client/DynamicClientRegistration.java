package org.azidp4j.client;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.request.ClientRequest;
import org.azidp4j.client.request.ClientRequestParser;
import org.azidp4j.client.request.InternalClientRequest;
import org.azidp4j.client.response.ClientDeleteResponse;
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

    public DynamicClientRegistration(
            AzIdPConfig config,
            ClientStore clientStore,
            ClientValidator customizableClientValidator,
            AccessTokenService accessTokenService) {
        this.config = config;
        this.clientStore = clientStore;
        this.clientValidator = new InternalClientValidator(config);
        this.customizableClientValidator =
                customizableClientValidator != null ? customizableClientValidator : client -> {};
        this.accessTokenService = accessTokenService;
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
                var grantType = GrantType.of(g);
                if (grantType == null) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_client_metadata"));
                }
                grantTypes.add(grantType);
            }
        }

        Set<ResponseType> responseTypes = new HashSet<>(); // TODO should be Set<Set<ResponseType>>
        if (request.responseTypes == null) {
            // default
            responseTypes.add(ResponseType.code);
        } else {
            for (String r : request.responseTypes) {
                var responseType = ResponseType.of(r);
                if (responseType == null) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_client_metadata"));
                }
                responseTypes.add(responseType);
            }
        }

        var applicationType = ApplicationType.WEB;
        if (request.applicationType != null) {
            applicationType = ApplicationType.of(request.applicationType);
            if (applicationType == null) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_client_metadata"));
            }
        }

        var tokenEndpointAuthMethod = TokenEndpointAuthMethod.client_secret_basic;
        if (request.tokenEndpointAuthMethod != null) {
            var tam = TokenEndpointAuthMethod.of(request.tokenEndpointAuthMethod);
            if (tam == null) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_client_metadata"));
            }
            tokenEndpointAuthMethod = tam;
        }

        SigningAlgorithm tokenEndpointAuthSigningAlg = null;
        if (request.tokenEndpointAuthSigningAlg != null) {
            tokenEndpointAuthSigningAlg = SigningAlgorithm.of(request.tokenEndpointAuthSigningAlg);
            if (tokenEndpointAuthSigningAlg == null) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_client_metadata"));
            }
        }

        var idTokenSignedResponseAlg = SigningAlgorithm.RS256;
        if (request.idTokenSignedResponseAlg != null) {
            idTokenSignedResponseAlg = SigningAlgorithm.of(request.idTokenSignedResponseAlg);
            if (idTokenSignedResponseAlg == null) {
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
                        tokenEndpointAuthSigningAlg,
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
                        Instant.now().getEpochSecond() + config.accessTokenExpirationSec,
                        Instant.now().getEpochSecond(),
                        Set.of(config.issuer),
                        null);
        var res =
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
                        client.tokenEndpointAuthSigningAlg != null
                                ? client.tokenEndpointAuthSigningAlg.name()
                                : null,
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
        return new ClientRegistrationResponse(201, res);
    }

    // TODO if configure is not required conformance test, it will be removed
    public ClientRegistrationResponse configure(String clientId, ClientRequest req) {
        if (clientId == null) {
            throw new AssertionError();
        }
        InternalClientRequest request;
        try {
            request = clientRequestParser.parse(req);
        } catch (IllegalArgumentException e) {
            return new ClientRegistrationResponse(400, Map.of("error", "invalid_client_metadata"));
        }
        var client = clientStore.find(clientId).orElseThrow(AssertionError::new);
        var grantTypes = client.grantTypes;
        if (request.grantTypes != null) {
            grantTypes = new HashSet<>();
            for (String g : request.grantTypes) {
                var grantType = GrantType.of(g);
                if (grantType == null) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_client_metadata"));
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

        var applicationType = ApplicationType.WEB;
        if (request.applicationType != null) {
            applicationType = ApplicationType.of(request.applicationType);
            if (applicationType == null) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_client_metadata"));
            }
        }

        var tokenEndpointAuthMethod = client.tokenEndpointAuthMethod;
        if (request.tokenEndpointAuthMethod != null) {
            var tam = TokenEndpointAuthMethod.of(request.tokenEndpointAuthMethod);
            if (tam == null) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_client_metadata"));
            }
            tokenEndpointAuthMethod = tam;
        }

        SigningAlgorithm tokenEndpointAuthSigningAlg = client.tokenEndpointAuthSigningAlg;
        if (request.tokenEndpointAuthSigningAlg != null) {
            tokenEndpointAuthSigningAlg = SigningAlgorithm.of(request.tokenEndpointAuthSigningAlg);
            if (tokenEndpointAuthSigningAlg == null) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_client_metadata"));
            }
        }

        var responseTypes = client.responseTypes;
        if (request.responseTypes != null) {
            for (String r : request.responseTypes) {
                var responseType = ResponseType.of(r);
                if (responseType == null) {
                    return new ClientRegistrationResponse(
                            400, Map.of("error", "invalid_client_metadata"));
                }
                responseTypes.add(responseType);
            }
        }
        var idTokenSignedResponseAlg = client.idTokenSignedResponseAlg;
        if (request.idTokenSignedResponseAlg != null) {
            var alg = SigningAlgorithm.of(request.idTokenSignedResponseAlg);
            if (alg == null) {
                return new ClientRegistrationResponse(
                        400, Map.of("error", "invalid_client_metadata"));
            }
            idTokenSignedResponseAlg = alg;
        }

        // TODO 指定された値だけ更新？全部更新？
        var updated =
                new Client(
                        client.clientId,
                        client.clientSecret,
                        redirectUris,
                        responseTypes,
                        applicationType,
                        grantTypes,
                        request.clientName != null ? request.clientName : client.clientName,
                        request.clientUri != null ? request.clientUri : client.clientUri,
                        request.logoUri != null ? request.logoUri : client.logoUri,
                        scope,
                        request.contacts != null ? request.contacts : client.contacts,
                        request.tosUri != null ? request.tosUri : client.tosUri,
                        request.policyUri != null ? request.policyUri : client.policyUri,
                        request.jwksUri != null ? request.jwksUri : client.jwksUri,
                        request.jwks != null ? request.jwks : client.jwks,
                        request.softwareId != null ? request.softwareId : client.softwareId,
                        request.softwareVersion != null
                                ? request.softwareVersion
                                : client.softwareVersion,
                        tokenEndpointAuthMethod,
                        tokenEndpointAuthSigningAlg,
                        idTokenSignedResponseAlg,
                        request.defaultMaxAge != null
                                ? request.defaultMaxAge
                                : client.defaultMaxAge,
                        request.requireAuthTime != null
                                ? request.requireAuthTime
                                : client.requireAuthTime,
                        request.initiateLoginUri != null
                                ? request.initiateLoginUri
                                : client.initiateLoginUri);
        try {
            clientValidator.validate(updated);
            customizableClientValidator.validate(client);
        } catch (IllegalArgumentException e) {
            return new ClientRegistrationResponse(400, Map.of("error", "invalid_client_metadata"));
        }
        clientStore.save(updated);
        var res =
                MapUtil.nullRemovedMap(
                        "client_id",
                        updated.clientId,
                        "client_secret",
                        updated.clientSecret,
                        "redirect_uris",
                        updated.redirectUris,
                        "grant_types",
                        updated.grantTypes.stream().map(Enum::name).collect(Collectors.toSet()),
                        "application_type",
                        updated.applicationType.name().toLowerCase(),
                        "client_uri",
                        updated.clientUri,
                        "logo_uri",
                        updated.logoUri,
                        "response_types",
                        updated.responseTypes.stream().map(Enum::name).collect(Collectors.toSet()),
                        "scope",
                        updated.scope,
                        "contacts",
                        updated.contacts,
                        "jwks_uri",
                        updated.jwksUri,
                        "jwks",
                        updated.jwks != null ? updated.jwks.toJSONObject() : null,
                        "software_id",
                        updated.softwareId,
                        "software_version",
                        updated.softwareVersion,
                        "token_endpoint_auth_method",
                        updated.tokenEndpointAuthMethod.name(),
                        "token_endpoint_auth_signing_alg",
                        updated.tokenEndpointAuthSigningAlg != null
                                ? updated.tokenEndpointAuthSigningAlg.name()
                                : null,
                        "id_token_signed_response_alg",
                        updated.idTokenSignedResponseAlg.name(),
                        "default_max_age",
                        updated.defaultMaxAge,
                        "require_auth_time",
                        updated.requireAuthTime,
                        "initiate_login_uri",
                        updated.initiateLoginUri);
        Optional.ofNullable(updated.clientName).ifPresent(v -> res.putAll(v.toMap()));
        Optional.ofNullable(updated.tosUri).ifPresent(v -> res.putAll(v.toMap()));
        Optional.ofNullable(updated.policyUri).ifPresent(v -> res.putAll(v.toMap()));
        return new ClientRegistrationResponse(200, res);
    }

    public ClientDeleteResponse delete(String clientId) {
        clientStore.remove(clientId);
        return new ClientDeleteResponse(204, null);
    }
}
