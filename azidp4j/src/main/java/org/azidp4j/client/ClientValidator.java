package org.azidp4j.client;

import java.net.URI;
import java.net.URISyntaxException;

public class ClientValidator {
    public void validate(Client client) {
        if (client.jwks != null && client.jwksUri != null) {
            throw new IllegalArgumentException();
        }
        if (client.tokenEndpointAuthMethod == TokenEndpointAuthMethod.none
                && client.grantTypes.contains(GrantType.client_credentials)) {
            throw new IllegalArgumentException();
        }

        // Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https
        // scheme as redirect_uris;they MUST NOT use localhost as the hostname. Native Clients MUST
        // only register redirect_uris using custom URI schemes or URLs using the http: scheme with
        // localhost as the hostname.
        if (client.applicationType == ApplicationType.WEB
                && client.grantTypes.contains(GrantType.implicit)) {
            for (String u : client.redirectUris) {
                try {
                    var uri = new URI(u);
                    if (!uri.getScheme().equals("https") || uri.getHost().equals("localhost")) {
                        throw new IllegalArgumentException();
                    }
                } catch (URISyntaxException e) {
                    throw new IllegalArgumentException();
                }
            }
        }

        if (client.applicationType == ApplicationType.NATIVE) {
            for (String u : client.redirectUris) {
                try {
                    var uri = new URI(u);
                    switch (uri.getScheme()) {
                        case "https" -> {
                            throw new IllegalArgumentException();
                        }
                        case "http" -> {
                            if (!uri.getHost().equals("localhost")) {
                                throw new IllegalArgumentException();
                            }
                        }
                    }
                } catch (URISyntaxException e) {
                    throw new IllegalArgumentException();
                }
            }
        }

        if (client.initiateLoginUri != null) {
            try {
                var initiateLoginUri = new URI(client.initiateLoginUri);
                if (!initiateLoginUri.isAbsolute()) {
                    throw new IllegalArgumentException();
                }
                if (!initiateLoginUri.getScheme().equals("https")) {
                    throw new IllegalArgumentException();
                }
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException();
            }
        }

        if (client.defaultMaxAge != null) {
            if (client.defaultMaxAge <= 0) {
                throw new IllegalArgumentException();
            }
        }
    }
}
