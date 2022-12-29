package org.azidp4j.authorize.authorizationcode;

import java.util.Arrays;
import java.util.List;

public class AcrValuesParser {

    /** Fix using acrValues */
    public static List<String> acrValues(
            String requestedAcrValues,
            List<String> defaultAcrValues,
            List<String> acrValuesSupported) {
        // if authorization request doesn't have acr_values, using client.defaultAcrValues
        List<String> acrValues =
                requestedAcrValues != null
                        ? Arrays.stream(requestedAcrValues.split(" ")).toList()
                        : List.of();
        if ((acrValues.isEmpty()) && defaultAcrValues != null && !defaultAcrValues.isEmpty()) {
            acrValues = defaultAcrValues;
        }
        // validate all acr_values satisfy acrValuesSupported
        if (acrValuesSupported != null && !acrValuesSupported.containsAll(acrValues)) {
            // acr_values is unsupported
            throw new IllegalArgumentException("unsupported acrValues");
        }

        return acrValues;
    }
}
