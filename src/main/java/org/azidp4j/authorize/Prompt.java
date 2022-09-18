package org.azidp4j.authorize;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public enum Prompt {
    none,
    login,
    consent,
    select_account,
    // authorization request has no prompt
    no_prompt;

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
            return no_prompt;
        }
        switch (prompt) {
            case "none":
                return none;
            case "login":
                return login;
            case "consent":
                return consent;
            case "select_account":
                return select_account;
            default:
                return null;
        }
    }
}
