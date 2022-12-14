package org.azidp4j.client;

public enum TokenEndpointAuthMethod {
    client_secret_post,
    client_secret_basic,
    client_secret_jwt,
    private_key_jwt,
    none;

    public static TokenEndpointAuthMethod of(String value) {
        if (value == null) {
            return null;
        }
        return switch (value) {
            case "client_secret_post" -> client_secret_post;
            case "client_secret_basic" -> client_secret_basic;
            case "client_secret_jwt" -> client_secret_jwt;
            case "private_key_jwt" -> private_key_jwt;
            case "none" -> none;
            default -> throw new IllegalArgumentException(value + " is not supported");
        };
    }
}
