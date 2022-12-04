package org.azidp4j.authorize.request;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public enum ResponseType { // TODO
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
        return switch (responseType) {
            case "code" -> code;
            case "token" -> token;
            case "id_token" -> id_token;
            case "none" -> none;
            default -> null;
        };
    }
}
