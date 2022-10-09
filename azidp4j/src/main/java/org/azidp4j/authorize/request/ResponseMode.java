package org.azidp4j.authorize.request;

import java.util.Set;

public enum ResponseMode {
    query,
    fragment;

    private static ResponseMode of(String responseMode) {
        if (responseMode == null) {
            return null;
        }
        return switch (responseMode) {
            case "fragment" -> fragment;
            case "query" -> query;
            default -> null;
        };
    }

    public static ResponseMode of(
            String requestedResponseMode, Set<ResponseType> requestedResponseTypes) {
        var defaultResponseMode = defaultValue(requestedResponseTypes);
        if (requestedResponseTypes.isEmpty()) {
            // illegal
            return null;
        }
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

        // multiple response type and id_token are only allowed "fragment"
        if (of(requestedResponseMode) == defaultResponseMode) {
            // multiple
            return defaultResponseMode;
        } else {
            // illegal
            return null;
        }
    }

    private static ResponseMode defaultValue(Set<ResponseType> requestedResponseTypes) {
        // default
        if (requestedResponseTypes.contains(ResponseType.none)
                && requestedResponseTypes.size() != 1) {
            // illegal
            return null;
        }
        if (requestedResponseTypes.contains(ResponseType.token)
                || requestedResponseTypes.contains(ResponseType.id_token)) {
            return fragment;
        } else {
            return query;
        }
    }
}
