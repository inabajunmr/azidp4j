package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import org.azidp4j.authorize.request.ResponseType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ResponseTypeTest {

    @ParameterizedTest
    @CsvSource({
        "code, code",
        "token, token",
        "id_token, id_token",
        "none, none",
    })
    void parseSingle(String responseTypes, String result) {
        assertEquals(1, ResponseType.parse(responseTypes).size());
        assertEquals(result, ResponseType.parse(responseTypes).stream().findFirst().get().name());
    }

    @Test
    void parseSingleIllegal() {
        assertNull(ResponseType.parse("illegal"));
    }

    @Test
    void parseDouble() {
        var actual = ResponseType.parse("code token");
        assertEquals(2, actual.size());
        assertTrue(actual.containsAll(Set.of(ResponseType.code, ResponseType.token)));
    }

    @Test
    void parseDoubleIllegal() {
        assertNull(ResponseType.parse("code illegal"));
    }
}
