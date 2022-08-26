package org.azidp4j.authorize;

public enum ResponseType {
    code;

    static ResponseType of(String responseType) {
        if(responseType == null) {
            return null;
        }
        switch (responseType) {
            case "code": return code;
            default: return null;
        }
    }
}
