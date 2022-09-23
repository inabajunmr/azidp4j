package org.azidp4j.token;

public enum TokenEndpointAuthMethod {
    // TODO client_secret_post,
    client_secret_basic,
    // TODO client_secret_jwt,
    // TODO private_key_jwt,
    none;

    public static TokenEndpointAuthMethod of(String value) {
        if (value == null) {
            return null;
        }
        switch (value) {
            case "client_secret_basic":
                return client_secret_basic;
            case "none":
                return none;
            default:
                return null;
        }
    }
}
