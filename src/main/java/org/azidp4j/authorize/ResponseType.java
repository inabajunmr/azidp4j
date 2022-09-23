package org.azidp4j.authorize;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public enum ResponseType {
    code,
    token,
    id_token,
    none;

    public static Set<ResponseType> parse(String responseType) {
        if (responseType == null) {
            return null;
        }
        var responseTypes =
                Arrays.stream(responseType.split(" "))
                        .map(ResponseType::of)
                        .collect(Collectors.toSet());
        if (responseTypes.contains(null)) {
            return null;
        }

        return responseTypes;
    }

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
