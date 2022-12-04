package org.azidp4j.authorize.request;

import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public enum Prompt { // TODO
    none,
    login,
    consent,
    select_account,
    // authorization request has no prompt
    no_prompt;

    public static Set<Prompt> parse(String prompt) {
        if (prompt == null) {
            return Set.of(no_prompt);
        }
        return Arrays.stream(prompt.split(" "))
                .map(Prompt::of)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    private static Prompt of(String prompt) {
        return switch (prompt) {
            case "none" -> none;
            case "login" -> login;
            case "consent" -> consent;
            case "select_account" -> select_account;
            default -> null;
        };
    }
}
