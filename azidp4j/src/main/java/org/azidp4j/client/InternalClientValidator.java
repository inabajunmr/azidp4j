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
                    case "https" -> {
                        throw new IllegalArgumentException("native client can't support https");
                    }
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
    }
}
