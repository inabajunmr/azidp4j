package org.azidp4j.authorize.request;

import java.util.Set;

public enum ResponseMode {
    query,
    fragment;

    public static ResponseMode of(
            String requestedResponseMode, Set<ResponseType> requestedResponseTypes) {
        var defaultResponseMode = defaultValue(requestedResponseTypes);
        if (requestedResponseMode == null) {
            // default
            return defaultResponseMode;
        }

        if (requestedResponseTypes.size() == 1) {
            // code/token/none are allowed requested response mode
            if (requestedResponseTypes.contains(ResponseType.code)
                    || requestedResponseTypes.contains(ResponseType.token)
                    || requestedResponseTypes.contains(ResponseType.none)) {
                return of(requestedResponseMode);
            }
        }

        // multiple response or response type is single 'id_token'
        // these case are only allowed "fragment"
        if (of(requestedResponseMode) == fragment) {
            // multiple
            return defaultResponseMode;
        } else {
            // illegal
            throw new IllegalArgumentException(
                    "multiple response types or id_token response type are only allowed fragment");
        }
    }

    private static ResponseMode of(String responseMode) {
        if (responseMode == null) {
            return null;
        }
        return switch (responseMode) {
            case "fragment" -> fragment;
            case "query" -> query;
            default -> throw new IllegalArgumentException(responseMode + " is not supported");
        };
    }

    private static ResponseMode defaultValue(Set<ResponseType> requestedResponseTypes) {
        // default
        if (requestedResponseTypes.contains(ResponseType.token)
                || requestedResponseTypes.contains(ResponseType.id_token)) {
            return fragment;
        } else {
            return query;
        }
    }
}
