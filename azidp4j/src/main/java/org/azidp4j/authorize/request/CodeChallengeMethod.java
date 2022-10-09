package org.azidp4j.authorize.request;

public enum CodeChallengeMethod {
    PLAIN,
    S256;

    public static CodeChallengeMethod of(String codeChallengeMethod) {
        if (codeChallengeMethod == null) {
            // default
            return S256;
        }
        return switch (codeChallengeMethod) {
            case "PLAIN" -> PLAIN;
            case "S256" -> S256;
            default -> null;
        };
    }
}
