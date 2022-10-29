package org.azidp4j.client;

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
            default -> null;
        };
    }
}
