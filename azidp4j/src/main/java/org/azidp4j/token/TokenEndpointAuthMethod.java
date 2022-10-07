package org.azidp4j.token;

public enum TokenEndpointAuthMethod {
    client_secret_post,
    client_secret_basic,
    // TODO client_secret_jwt,
    // TODO private_key_jwt,
    none;

    public static TokenEndpointAuthMethod of(String value) {
        if (value == null) {
            return null;
        }
        return switch (value) {
            case "client_secret_post" -> client_secret_post;
            case "client_secret_basic" -> client_secret_basic;
            case "none" -> none;
            default -> null;
        };
    }
}
