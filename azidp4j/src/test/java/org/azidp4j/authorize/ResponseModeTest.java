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
        try {
            ResponseMode.of("invalid", Set.of(ResponseType.code));
            fail();
        } catch (IllegalArgumentException e) {
        }
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
        "fragment, code,     fragment",
        "fragment, none,     fragment",
    })
    void testSingle_Valid(
            String requestedResponseMode,
            ResponseType responseType,
            ResponseMode resultResponseMode) {
        assertEquals(
                resultResponseMode, ResponseMode.of(requestedResponseMode, Set.of(responseType)));
    }

    @ParameterizedTest
    @CsvSource({
        "query   , id_token",
    })
    void testSingle_InValid(String requestedResponseMode, ResponseType responseType) {
        try {
            ResponseMode.of(requestedResponseMode, Set.of(responseType));
            fail();
        } catch (IllegalArgumentException e) {
        }
    }

    @ParameterizedTest
    @CsvSource({
        "        , code, token,          fragment",
        "        , code, id_token,       fragment",
        "        , id_token, token,      fragment",
        "fragment, code, token,          fragment",
        "fragment, code, id_token,       fragment",
        "fragment, id_token, token,      fragment",
    })
    void testDouble_Valid(
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
        "query   , code, token",
        "query   , code, id_token",
        "query   , id_token, token",
    })
    void testDouble_Invalid(
            String requestedResponseMode, ResponseType responseType1, ResponseType responseType2) {
        try {
            ResponseMode.of(requestedResponseMode, Set.of(responseType1, responseType2));
            fail();
        } catch (IllegalArgumentException e) {
        }
    }

    @ParameterizedTest
    @CsvSource({
        "        , code, id_token, token, fragment",
        "fragment, code, id_token, token, fragment",
    })
    void testTriple_Valid(
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

    @ParameterizedTest
    @CsvSource({
        "query   , code, id_token, token, ",
    })
    void testTriple_InValid(
            String requestedResponseMode,
            ResponseType responseType1,
            ResponseType responseType2,
            ResponseType responseType3) {
        try {
            ResponseMode.of(
                    requestedResponseMode, Set.of(responseType1, responseType2, responseType3));
            fail();
        } catch (IllegalArgumentException e) {
        }
    }
}
