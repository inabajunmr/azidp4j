package org.azidp4j.client.request;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.azidp4j.RequestParserUtil;
import org.junit.jupiter.api.Test;

class RequestParserUtilTest {

    @Test
    void valuesToStringSet_Array() {
        assertEquals(
                Set.of("a", "b", "c"),
                RequestParserUtil.valuesToStringSet(new String[] {"a", "b", "c"}));
    }

    @Test
    void valuesToStringSet_List() {
        assertEquals(
                Set.of("a", "b", "c"), RequestParserUtil.valuesToStringSet(List.of("a", "b", "c")));
    }

    @Test
    void valuesToStringSet_Null() {
        assertNull(RequestParserUtil.valuesToStringSet(null));
    }

    @Test
    void valuesToStringSet_TypeError_ContainsNotString() {
        try {
            RequestParserUtil.valuesToStringSet(List.of("a", 1, "b"));
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }

    @Test
    void valuesToStringSet_TypeError_NotCollection() {
        try {
            RequestParserUtil.valuesToStringSet(1);
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }

    @Test
    void valuesToStringList_Array() {
        assertEquals(
                List.of("a", "b", "c"),
                RequestParserUtil.valuesToStringList(List.of("a", "b", "c")));
    }

    @Test
    void valuesToStringList_List() {
        assertEquals(
                List.of("a", "b", "c"),
                RequestParserUtil.valuesToStringList(List.of("a", "b", "c")));
    }

    @Test
    void valuesToStringList_Null() {
        assertNull(RequestParserUtil.valuesToStringList(null));
    }

    @Test
    void valuesToStringList_TypeError_ContainsNotString() {
        try {
            RequestParserUtil.valuesToStringList(List.of("a", 1, "b"));
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }

    @Test
    void valuesToStringList_TypeError_NotCollection() {
        try {
            RequestParserUtil.valuesToStringList(1);
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }

    @Test
    void valuesToHumanReadable() {
        var actual =
                RequestParserUtil.valuesToHumanReadable(
                        "client_name",
                        Map.of(
                                "client_name",
                                "client",
                                "client_name#ja",
                                "クライアント",
                                "client_name#cn",
                                "客户"));
        assertEquals(
                Map.of("client_name", "client", "client_name#ja", "クライアント", "client_name#cn", "客户"),
                actual.toMap());
    }

    @Test
    void valuesToHumanReadable_NotFound() {
        var actual = RequestParserUtil.valuesToHumanReadable("client_id", Map.of("wow", "wow"));
        assertNull(actual);
    }

    @Test
    void valuesToHumanReadable_TypeError_Default() {
        try {
            RequestParserUtil.valuesToHumanReadable(
                    "client_name",
                    Map.of("client_name", 1, "client_name#ja", "クライアント", "client_name#cn", "客户"));
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }

    @Test
    void valuesToHumanReadable_TypeError_Tag() {
        try {
            RequestParserUtil.valuesToHumanReadable(
                    "client_name",
                    Map.of("client_name", "client", "client_name#ja", 1, "client_name#cn", "客户"));
            fail();
        } catch (IllegalArgumentException e) {
            // NOP
        }
    }

    @Test
    void valueToString() {
        var actual = RequestParserUtil.valueToString("key", Map.of("key", "value"));
        assertEquals("value", actual);
    }

    @Test
    void valueToString_NotFound() {
        var actual = RequestParserUtil.valueToString("notfound", Map.of("key", "value"));
        assertNull(actual);
    }
}
