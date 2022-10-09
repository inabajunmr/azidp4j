package org.azidp4j.authorize;

public enum Display {
    page,
    popup,
    touch,
    wap;

    public static Display of(String display) {
        if (display == null) {
            return null;
        }
        return switch (display) {
            case "page" -> page;
            case "popup" -> popup;
            case "touch" -> touch;
            case "wap" -> wap;
            default -> null;
        };
    }
}
