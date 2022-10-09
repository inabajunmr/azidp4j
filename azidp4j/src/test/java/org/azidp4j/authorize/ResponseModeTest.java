package org.azidp4j.authorize;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.request.ResponseType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ResponseModeTest {

    @Test
    void illegal() {
        assertNull(ResponseMode.of("invalid", Set.of(ResponseType.code)));
        assertNull(ResponseMode.of(null, Set.of(ResponseType.code, ResponseType.none)));
    }

    @ParameterizedTest
    @CsvSource({
        "        , token,    fragment",
        "        , id_token, fragment",
        "        , code,     query",
        "        , none,     query",
        "fragment, token,    fragment",
        "fragment, id_token, fragment",
        "query   , code,     query",
        "query   , none,     query",
        "query   , token,    query",
        "query   , id_token,",
        "fragment, code,     fragment",
        "fragment, none,     fragment",
    })
    void testSingle(
            String requestedResponseMode,
            ResponseType responseType,
            ResponseMode resultResponseMode) {
        assertEquals(
                resultResponseMode, ResponseMode.of(requestedResponseMode, Set.of(responseType)));
    }

    @ParameterizedTest
    @CsvSource({
        "        , code, token,          fragment",
        "        , code, id_token,       fragment",
        "        , id_token, token,      fragment",
        "fragment, code, token,          fragment",
        "fragment, code, id_token,       fragment",
        "fragment, id_token, token,      fragment",
        "query   , code, token,          ",
        "query   , code, id_token,       ",
        "query   , id_token, token,      ",
    })
    void testDouble(
            String requestedResponseMode,
            ResponseType responseType1,
            ResponseType responseType2,
            ResponseMode resultResponseMode) {
        assertEquals(
                resultResponseMode,
                ResponseMode.of(requestedResponseMode, Set.of(responseType1, responseType2)));
    }

    @ParameterizedTest
    @CsvSource({
        "        , code, id_token, token, fragment",
        "fragment, code, id_token, token, fragment",
        "query   , code, id_token, token, ",
    })
    void testTriple(
            String requestedResponseMode,
            ResponseType responseType1,
            ResponseType responseType2,
            ResponseType responseType3,
            ResponseMode resultResponseMode) {
        assertEquals(
                resultResponseMode,
                ResponseMode.of(
                        requestedResponseMode,
                        Set.of(responseType1, responseType2, responseType3)));
    }
}
