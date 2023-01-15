package org.azidp4j.client;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import org.azidp4j.AzIdPConfig;

public class InternalClientValidator {

    private final AzIdPConfig config;

    public InternalClientValidator(AzIdPConfig config) {
        this.config = config;
    }

    public void validate(Client client) {
        var redirectUris = new ArrayList<URI>();
        for (String u : client.redirectUris) {
            try {
                var uri = new URI(u);
                if (!uri.isAbsolute()) {
                    throw new IllegalArgumentException("illegal redirect uri");
                }
                redirectUris.add(uri);
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException("illegal redirect uri");
            }
        }

        if (!config.grantTypesSupported.containsAll(client.grantTypes)) {
            throw new IllegalArgumentException("unsupported grant types");
        }

        if (!config.responseTypeSupported.containsAll(client.responseTypes)) {
            throw new IllegalArgumentException("unsupported response types");
        }

        if (config.scopesSupported != null && client.scope != null) {
            if (!config.scopesSupported.containsAll(
                    Arrays.stream(client.scope.split(" ")).toList())) {
                throw new IllegalArgumentException("unsupported scope");
            }
        }
        if (client.jwks != null && client.jwksUri != null) {
            throw new IllegalArgumentException("jwks and jwksUri");
        }
        if (client.tokenEndpointAuthMethod == TokenEndpointAuthMethod.none
                && client.grantTypes.contains(GrantType.client_credentials)) {
            throw new IllegalArgumentException(
                    "tokenEndpoint doesn't required authentication but client_credential"
                            + " supported");
        }

        // token_endpoint_auth_method doesn't require signing alg, it causes error.
        if (client.tokenEndpointAuthMethod != null
                && !client.tokenEndpointAuthMethod.usingTokenAuthMethodSigningAlg
                && client.tokenEndpointAuthSigningAlg != null) {
            throw new IllegalArgumentException(
                    "tokenEndpointAuthMethod "
                            + client.tokenEndpointAuthMethod.name()
                            + " doesn't required tokenEndpointAuthSigningAlg");
        }
        // check auth method is supported
        if (client.tokenEndpointAuthMethod != null
                && !config.tokenEndpointAuthMethodsSupported.contains(
                        client.tokenEndpointAuthMethod)) {
            throw new IllegalArgumentException(
                    client.tokenEndpointAuthMethod + " is not supported");
        }
        // check algorithm is supported
        if (client.tokenEndpointAuthSigningAlg != null
                && !config.tokenEndpointAuthSigningAlgValuesSupported.contains(
                        client.tokenEndpointAuthSigningAlg)) {
            throw new IllegalArgumentException(
                    client.tokenEndpointAuthSigningAlg + " is not supported");
        }

        // introspection_endpoint_auth_method doesn't require signing alg, it causes error.
        if (client.introspectionEndpointAuthMethod != null
                && !client.introspectionEndpointAuthMethod.usingTokenAuthMethodSigningAlg
                && client.introspectionEndpointAuthSigningAlg != null) {
            throw new IllegalArgumentException(
                    "introspectionEndpointAuthMethod "
                            + client.introspectionEndpointAuthMethod.name()
                            + " doesn't required introspectionEndpointAuthSigningAlg");
        }
        // check auth method is supported
        if (client.introspectionEndpointAuthMethod != null
                && !config.introspectionEndpointAuthMethodsSupported.contains(
                        client.introspectionEndpointAuthMethod)) {
            throw new IllegalArgumentException(
                    client.introspectionEndpointAuthMethod + " is not supported");
        }
        // check algorithm is supported
        if (client.introspectionEndpointAuthSigningAlg != null
                && !config.introspectionEndpointAuthSigningAlgValuesSupported.contains(
                        client.introspectionEndpointAuthSigningAlg)) {
            throw new IllegalArgumentException(
                    client.introspectionEndpointAuthSigningAlg + " is not supported");
        }

        // revocation_endpoint_auth_method doesn't require signing alg, it causes error.
        if (client.revocationEndpointAuthMethod != null
                && !client.revocationEndpointAuthMethod.usingTokenAuthMethodSigningAlg
                && client.revocationEndpointAuthSigningAlg != null) {
            throw new IllegalArgumentException(
                    "revocationEndpointAuthMethod "
                            + client.revocationEndpointAuthMethod.name()
                            + " doesn't required revocationEndpointAuthSigningAlg");
        }
        // check auth method is supported
        if (client.revocationEndpointAuthMethod != null
                && !config.revocationEndpointAuthMethodsSupported.contains(
                        client.revocationEndpointAuthMethod)) {
            throw new IllegalArgumentException(
                    client.revocationEndpointAuthMethod + " is not supported");
        }
        // check algorithm is supported
        if (client.revocationEndpointAuthSigningAlg != null
                && !config.revocationEndpointAuthSigningAlgValuesSupported.contains(
                        client.revocationEndpointAuthSigningAlg)) {
            throw new IllegalArgumentException(
                    client.revocationEndpointAuthSigningAlg + " is not supported");
        }

        // Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https
        // scheme as redirect_uris;they MUST NOT use localhost as the hostname. Native Clients MUST
        // only register redirect_uris using custom URI schemes or URLs using the http: scheme with
        // localhost as the hostname.
        if (client.applicationType == ApplicationType.WEB
                && client.grantTypes.contains(GrantType.implicit)) {
            for (URI uri : redirectUris) {
                if (!uri.getScheme().equals("https") || uri.getHost().equals("localhost")) {
                    throw new IllegalArgumentException(
                            "web application can't supports http and localhost");
                }
            }
        }

        if (client.applicationType == ApplicationType.NATIVE) {
            for (URI uri : redirectUris) {
                switch (uri.getScheme()) {
                    case "https" -> throw new IllegalArgumentException(
                            "native client can't support https");
                    case "http" -> {
                        if (!uri.getHost().equals("localhost")) {
                            throw new IllegalArgumentException(
                                    "native client can't supports http schema except for"
                                            + " localhost");
                        }
                    }
                }
            }
        }

        if (client.initiateLoginUri != null) {
            try {
                var initiateLoginUri = new URI(client.initiateLoginUri);
                if (!initiateLoginUri.isAbsolute()) {
                    throw new IllegalArgumentException("illegal initiateLoginUri");
                }
                if (!initiateLoginUri.getScheme().equals("https")) {
                    throw new IllegalArgumentException("initiateLoginUri must be https");
                }
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException("illegal initiateLoginUri");
            }
        }

        if (client.defaultMaxAge != null) {
            if (client.defaultMaxAge <= 0) {
                throw new IllegalArgumentException("defaultMaxAge must be positive");
            }
        }

        if (config.acrValuesSupported != null
                && client.defaultAcrValues != null
                && !config.acrValuesSupported.containsAll(client.defaultAcrValues)) {
            throw new IllegalArgumentException(
                    "defaultAcrValues doesn't support at acrValuesSupported");
        }
    }
}
