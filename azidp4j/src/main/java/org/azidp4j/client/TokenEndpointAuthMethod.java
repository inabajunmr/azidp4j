package org.azidp4j.client;

public enum TokenEndpointAuthMethod {
    client_secret_post(false),
    client_secret_basic(false),
    client_secret_jwt(true),
    private_key_jwt(true),
    none(false);

    TokenEndpointAuthMethod(boolean usingTokenAuthMethodSigningAlg) {
        this.usingTokenAuthMethodSigningAlg = usingTokenAuthMethodSigningAlg;
    }

    public final boolean usingTokenAuthMethodSigningAlg;

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
