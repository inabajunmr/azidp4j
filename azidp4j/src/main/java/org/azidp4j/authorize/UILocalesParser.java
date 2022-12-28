package org.azidp4j.authorize;

import java.util.Arrays;
import java.util.List;

public class UILocalesParser {
    public static List<String> parseUiLocales(String uiLocales) {
        if (uiLocales == null) {
            return List.of();
        }

        return Arrays.stream(uiLocales.replaceAll(" +", " ").split(" ")).toList();
    }
}
