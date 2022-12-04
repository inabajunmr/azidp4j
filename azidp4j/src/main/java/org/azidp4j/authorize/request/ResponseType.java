package org.azidp4j.authorize.request;

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
            return Set.of();
        }
        var responseTypes =
                Arrays.stream(responseType.split(" "))
                        .map(ResponseType::of)
                        .collect(Collectors.toSet());

        return responseTypes;
    }

    private static ResponseType of(String responseType) {
        if (responseType == null) {
            throw new IllegalArgumentException("responseType is null.");
        }
        return switch (responseType) {
            case "code" -> code;
            case "token" -> token;
            case "id_token" -> id_token;
            case "none" -> none;
            default -> throw new IllegalArgumentException(responseType + " is not supported.");
        };
    }
}
