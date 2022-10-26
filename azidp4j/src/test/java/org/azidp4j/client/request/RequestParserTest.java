package org.azidp4j.client.request;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class RequestParserTest {

    @Test
    void valuesToStringSet_Array() {
        assertEquals(
                Set.of("a", "b", "c"),
                RequestParser.valuesToStringSet(new String[] {"a", "b", "c"}));
    }

    @Test
    void valuesToStringSet_List() {
        assertEquals(
                Set.of("a", "b", "c"), RequestParser.valuesToStringSet(List.of("a", "b", "c")));
    }

    @Test
    void valuesToStringSet_Null() {
        assertNull(RequestParser.valuesToStringSet(null));
    }

    @Test
    void valuesToStringList_Array() {
        assertEquals(
                List.of("a", "b", "c"), RequestParser.valuesToStringList(List.of("a", "b", "c")));
    }

    @Test
    void valuesToStringList_List() {
        assertEquals(
                List.of("a", "b", "c"), RequestParser.valuesToStringList(List.of("a", "b", "c")));
    }

    @Test
    void valuesToStringList_Null() {
        assertNull(RequestParser.valuesToStringList(null));
    }

    @Test
    void valuesToHumanReadable() {
        var actual =
                RequestParser.valuesToHumanReadable(
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
        var actual = RequestParser.valuesToHumanReadable("client_id", Map.of("wow", "wow"));
        assertNull(actual);
    }

    @Test
    void valueToString() {
        var actual = RequestParser.valueToString("key", Map.of("key", "value"));
        assertEquals("value", actual);
    }

    @Test
    void valueToString_NotFound() {
        var actual = RequestParser.valueToString("notfound", Map.of("key", "value"));
        assertNull(actual);
    }
}
