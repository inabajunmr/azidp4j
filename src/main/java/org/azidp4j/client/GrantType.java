package org.azidp4j.client;

public enum GrantType {
    authorization_code,
    implicit,
    client_credentials;

    public static GrantType of(String value) {
        if (value == null) {
            return null;
        }
        switch (value) {
            case "authorization_code":
                return authorization_code;
            case "implicit":
                return implicit;
            case "client_credentials":
                return client_credentials;
            default:
                return null;
        }
    }
}
