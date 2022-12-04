package org.azidp4j.client;

public enum GrantType { // TODO
    authorization_code,
    implicit,
    password,
    client_credentials,
    refresh_token;

    public static GrantType of(String value) {
        if (value == null) {
            return null;
        }
        return switch (value) {
            case "authorization_code" -> authorization_code;
            case "implicit" -> implicit;
            case "password" -> password;
            case "client_credentials" -> client_credentials;
            case "refresh_token" -> refresh_token;
            default -> null;
        };
    }
}
