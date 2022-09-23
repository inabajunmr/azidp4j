package org.azidp4j.authorize;

public enum CodeChallengeMethod {
    PLAIN,
    S256;

    public static CodeChallengeMethod of(String codeChallengeMethod) {
        if (codeChallengeMethod == null) {
            // default
            return S256;
        }
        switch (codeChallengeMethod) {
            case "PLAIN":
                return PLAIN;
            case "S256":
                return S256;
            default:
                return null;
        }
    }
}
