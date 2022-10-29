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
    void valuesToHumanReadable() {
        var actual =
                RequestParserUtil.valuesToHumanReadable(
                        "client_id",
                        Map.of(
                                "client_id",
                                "client",
                                "client_id#ja",
                                "クライアント",
                                "client_id#cn",
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
