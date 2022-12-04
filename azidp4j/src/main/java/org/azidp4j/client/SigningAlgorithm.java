package org.azidp4j.client;

public enum SigningAlgorithm {
    RS256,
    ES256,
    none;

    public static SigningAlgorithm of(String alg) {
        if (alg == null) {
            return null;
        }
        return switch (alg) {
            case "RS256" -> RS256;
            case "ES256" -> ES256;
            case "none" -> none;
            default -> throw new IllegalArgumentException(alg + " is not supported");
        };
    }
}
