package org.azidp4j.client;

/** https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata */
public enum ApplicationType {
    WEB,
    NATIVE;

    public static ApplicationType of(String value) {
        if (value == null) {
            return null;
        }
        return switch (value) {
            case "web" -> WEB;
            case "native" -> NATIVE;
            default -> throw new IllegalArgumentException(value + " is not supported");
        };
    }
}
