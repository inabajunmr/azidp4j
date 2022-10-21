package org.azidp4j.revocation.request;

public enum TokenTypeHint {
    access_token,
    refresh_token;

    public static TokenTypeHint of(String hint) {
        if (hint == null) {
            return null;
        }
        return switch (hint) {
            case "access_token" -> access_token;
            case "refresh_token" -> refresh_token;
            default -> null;
        };
    }
}
