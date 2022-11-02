package org.azidp4j;

import java.util.*;
import java.util.stream.Collectors;
import org.azidp4j.util.HumanReadable;

public class RequestParserUtil {

    public static Set<String> valuesToStringSet(Object values) {
        if (values == null) {
            return null;
        }
        if (values instanceof Collection cast) {
            cast.stream()
                    .forEach(
                            v -> {
                                if (!(v instanceof String)) {
                                    throw new IllegalArgumentException();
                                }
                            });
            return (Set<String>) cast.stream().collect(Collectors.toSet());
        } else if (values instanceof String[]) {
            return Arrays.stream((String[]) values).collect(Collectors.toSet());
        } else {
            throw new IllegalArgumentException();
        }
    }

    public static List<String> valuesToStringList(Object values) {
        if (values == null) {
            return null;
        }
        if (values instanceof List cast) {
            cast.stream()
                    .forEach(
                            v -> {
                                if (!(v instanceof String)) {
                                    throw new IllegalArgumentException();
                                }
                            });
            return ((List<String>) cast.stream().toList());
        } else if (values instanceof String[]) {
            return Arrays.stream((String[]) values).collect(Collectors.toList());
        } else {
            throw new IllegalArgumentException();
        }
    }

    public static HumanReadable<String> valuesToHumanReadable(
            String key, Map<String, Object> parameters) {
        String defaultValue = null;
        if (parameters.containsKey(key)) {
            if (parameters.get(key) instanceof String cast) {
                defaultValue = cast;
            } else {
                throw new IllegalArgumentException();
            }
        }
        var map = new HashMap<String, String>();
        parameters.keySet().stream()
                .filter(k -> k.startsWith(key + "#"))
                .forEach(
                        k -> {
                            if (parameters.get(k) instanceof String cast) {
                                map.put(k.substring(k.indexOf('#') + 1), cast);
                            } else {
                                throw new IllegalArgumentException();
                            }
                        });
        if (defaultValue == null && map.isEmpty()) {
            return null;
        }
        return new HumanReadable<>(key, defaultValue, map);
    }

    public static String valueToString(String key, Map<String, Object> parameters) {
        if (parameters.containsKey(key)) {
            var val = parameters.get(key);
            if (val == null) {
                return null;
            }
            if (val instanceof String cast) {
                return cast;
            } else {
                throw new IllegalArgumentException();
            }
        }
        return null;
    }
}
