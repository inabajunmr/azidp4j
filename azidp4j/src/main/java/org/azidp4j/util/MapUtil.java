package org.azidp4j.util;

import java.util.HashMap;
import java.util.Map;

public class MapUtil {

    public static Map<String, String> nullRemovedStringMap(String... kv) {
        if (kv.length % 2 != 0) {
            throw new AssertionError();
        }

        var removed = new HashMap<String, String>();
        for (int i = 0; i < kv.length; i += 2) {
            var k = kv[i];
            var v = kv[i + 1];
            if (v != null) {
                removed.put(k, v);
            }
        }
        return removed;
    }

    public static Map<String, Object> nullRemovedMap(Object... kv) {
        if (kv.length % 2 != 0) {
            throw new AssertionError();
        }

        var removed = new HashMap<String, Object>();
        for (int i = 0; i < kv.length; i += 2) {
            var k = (String) kv[i];
            var v = kv[i + 1];
            if (v != null) {
                removed.put(k, v);
            }
        }
        return removed;
    }

    public static Map<String, Object> ofNullable(Object... kv) {
        if (kv.length % 2 != 0) {
            throw new AssertionError();
        }

        var result = new HashMap<String, Object>();
        for (int i = 0; i < kv.length; i += 2) {
            var k = (String) kv[i];
            var v = kv[i + 1];
            result.put(k, v);
        }
        return result;
    }
}
