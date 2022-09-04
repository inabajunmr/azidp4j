package org.azidp4j.client;

public enum GrantType {
    authorization_code,
    implicit,
    password,
    client_credentials,
    refresh_token;

    public static GrantType of(String value) {
        if (value == null) {
            return null;
        }
        switch (value) {
            case "authorization_code":
                return authorization_code;
            case "implicit":
                return implicit;
            case "password":
                return password;
            case "client_credentials":
                return client_credentials;
            case "refresh_token":
                return refresh_token;
            default:
                return null;
        }
    }
}
