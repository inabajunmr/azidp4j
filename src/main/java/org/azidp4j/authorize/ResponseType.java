package org.azidp4j.authorize;

public enum ResponseType {
    code,
    token;

    public static ResponseType of(String responseType) {
        if (responseType == null) {
            return null;
        }
        switch (responseType) {
            case "code":
                return code;
            case "token":
                return token;
            default:
                return null;
        }
    }
}
