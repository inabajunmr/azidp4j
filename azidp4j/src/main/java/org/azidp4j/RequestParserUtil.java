package org.azidp4j;

import java.util.*;
import java.util.stream.Collectors;
import org.azidp4j.util.HumanReadable;

public class RequestParserUtil {

    public static Set<String> valuesToStringSet(Object values) {
        if (values == null) {
            return null;
        }
        if (values instanceof Collection) {
            var onlyString =
                    ((Collection<?>) values)
                            .stream().filter(v -> v instanceof String).collect(Collectors.toSet());
            return ((Set<String>) onlyString);
        } else if (values instanceof String[]) {
            return Arrays.stream((String[]) values).collect(Collectors.toSet());
        }
        return Set.of();
    }

    public static List<String> valuesToStringList(Object values) {
        if (values == null) {
            return null;
        }
        if (values instanceof Collection) {
            var onlyString =
                    ((Collection<?>) values)
                            .stream().filter(v -> v instanceof String).collect(Collectors.toList());
            return ((List<String>) onlyString);
        } else if (values instanceof String[]) {
            return Arrays.stream((String[]) values).collect(Collectors.toList());
        }
        return List.of();
    }

    public static HumanReadable<String> valuesToHumanReadable(
            String key, Map<String, Object> parameters) {
        var defaultValue = parameters.containsKey(key) ? (String) parameters.get(key) : null;
        var map = new HashMap<String, String>();
        parameters.keySet().stream()
                .filter(k -> k.startsWith(key + "#"))
                .forEach(
                        k -> {
                            map.put(k.substring(k.indexOf('#') + 1), parameters.get(k).toString());
                        });
        if (defaultValue == null && map.isEmpty()) {
            return null;
        }
        return new HumanReadable<>("client_name", defaultValue, map);
    }

    public static String valueToString(String key, Map<String, Object> parameters) {
        return parameters.containsKey(key) ? parameters.get(key).toString() : null;
    }
}
