package org.azidp4j.authorize;

public enum ResponseType {
    code,
    token,
    id_token,
    none;
    // TODO id_token
    // TODO none
    // TODO multi value

    public static ResponseType of(String responseType) {
        if (responseType == null) {
            return null;
        }
        switch (responseType) {
            case "code":
                return code;
            case "token":
                return token;
            case "id_token":
                return id_token;
            case "none":
                return none;
            default:
                return null;
        }
    }
}
