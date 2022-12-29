package org.azidp4j.authorize.authorizationcode;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AcrValuesParserTest {

    @Test
    @DisplayName("requestedAcrValues=acr1 acr2, defaultAcrValues=null, acrValuesSupported=acr3")
    void unsupportedAcrValues1() {
        assertThrows(
                IllegalArgumentException.class,
                () -> AcrValuesParser.acrValues("acr1 acr2", null, List.of("acr3")));
    }

    @Test
    @DisplayName(
            "requestedAcrValues=acr1 acr2, defaultAcrValues=acr1,acr2, acrValuesSupported=acr3")
    void unsupportedAcrValues2() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        AcrValuesParser.acrValues(
                                "acr1 acr2", List.of("acr1", "acr2"), List.of("acr3")));
    }

    @Test
    @DisplayName(
            "requestedAcrValues=null, defaultAcrValues=acr1,acr2,acr3,"
                    + " acrValuesSupported=acr1,acr2")
    void unsupportedDefault() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        AcrValuesParser.acrValues(
                                null, List.of("acr1", "acr2", "acr3"), List.of("acr1", "acr2")));
    }

    @Test
    @DisplayName(
            "requestedAcrValues=acr1 acr2, defaultAcrValues=null,"
                    + " acrValuesSupported=acr1,acr2,acr3")
    void supportedAcrValues1() {
        var actual = AcrValuesParser.acrValues("acr1 acr2", null, List.of("acr1", "acr2", "acr3"));
        assertTrue(actual.containsAll(List.of("acr1", "acr2")));
    }

    @Test
    @DisplayName(
            "requestedAcrValues=acr1 acr2, defaultAcrValues=acr2,acr3,"
                    + " acrValuesSupported=acr1,acr2,acr3")
    void supportedAcrValues2() {
        var actual =
                AcrValuesParser.acrValues(
                        "acr1 acr2", List.of("acr2", "acr3"), List.of("acr1", "acr2", "acr3"));
        assertTrue(actual.containsAll(List.of("acr1", "acr2")));
    }

    @Test
    @DisplayName(
            "requestedAcrValues=null, defaultAcrValues=acr2,acr3,"
                    + " acrValuesSupported=acr1,acr2,acr3")
    void supportedDefault() {
        var actual =
                AcrValuesParser.acrValues(
                        null, List.of("acr2", "acr3"), List.of("acr1", "acr2", "acr3"));
        assertTrue(actual.containsAll(List.of("acr2", "acr3")));
    }
}
