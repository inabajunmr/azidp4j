package org.azidp4j.authorize;

public enum Prompt {
    none,
    login;

    public static Prompt of(String responseType) {
        if (responseType == null) {
            return null;
        }
        switch (responseType) {
            case "none":
                return none;
            case "login":
                return login;
            default:
                return null;
        }
    }
}
