package org.azidp4j.authorize;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public enum Prompt {
    none,
    login,
    consent;

    // TODO

    public static Set<Prompt> parse(String prompt) {
        if (prompt == null) {
            return Set.of();
        }
        return Arrays.stream(prompt.split(" "))
                .map(Prompt::of)
                .filter(v -> v != null)
                .collect(Collectors.toSet());
    }

    private static Prompt of(String prompt) {
        if (prompt == null) {
            return null;
        }
        switch (prompt) {
            case "none":
                return none;
            case "login":
                return login;
            case "consent":
                return consent;
            default:
                return null;
        }
    }
}
