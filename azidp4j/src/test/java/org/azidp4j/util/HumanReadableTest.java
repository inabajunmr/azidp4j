package org.azidp4j.util;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import org.junit.jupiter.api.Test;

class HumanReadableTest {

    @Test
    void test() {
        var h = new HumanReadable<>("key", "default", Map.of("ja", "ja value", "en", "en value"));
        assertEquals("key", h.getKey());
        assertEquals("default", h.getDefault());
        assertEquals("default", h.get(null));
        assertEquals("ja value", h.get("ja"));
        assertEquals("en value", h.get("en"));
        var m = h.toMap();
        assertEquals("default", m.get("key"));
        assertEquals("ja value", m.get("key#ja"));
        assertEquals("en value", m.get("key#en"));
    }
}
