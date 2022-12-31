package org.azidp4j.springsecuritysample.claims;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;

public class ClaimsParameterParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static ClaimsParameters parse(String claimsStr) {
        if (claimsStr == null) {
            return new ClaimsParameters(Map.of(), Map.of());
        }
        try {
            var tree = MAPPER.readTree(claimsStr);
            return new ClaimsParameters(
                    extract(tree.get("id_token")), extract(tree.get("userinfo")));
        } catch (JsonProcessingException e) {
            return new ClaimsParameters(Map.of(), Map.of());
        }
    }

    private static Map<String, ClaimsParameter> extract(JsonNode idTokenOrUserInfo) {
        if (idTokenOrUserInfo == null) {
            return Map.of();
        }
        Map<String, ClaimsParameter> claimsParameters = new HashMap<>();
        idTokenOrUserInfo
                .fieldNames()
                .forEachRemaining(
                        claimName -> {
                            var claim = idTokenOrUserInfo.get(claimName);
                            var isEssential = false;
                            if (claim.has("essential")) {
                                isEssential =
                                        claim.get("essential").isBoolean()
                                                && claim.get("essential").booleanValue();
                            }
                            // parse each claims
                            if (claim.has("value")) {
                                // value
                                var valueNode = claim.get("value");
                                var value = claimsValue(valueNode);
                                if (value.isPresent()) {
                                    claimsParameters.put(
                                            claimName,
                                            new ClaimsParameter(List.of(value.get()), isEssential));
                                    return;
                                }
                            }

                            // values
                            if (claim.has("values") && claim.get("values").isArray()) {
                                List<ClaimsValue> claimsValues = new ArrayList<>();
                                for (JsonNode node : claim.get("values")) {
                                    System.out.println("ss");
                                    var arrayValue = claimsValue(node);
                                    arrayValue.ifPresent(claimsValues::add);
                                }
                                if (!claimsValues.isEmpty()) {
                                    claimsParameters.put(
                                            claimName,
                                            new ClaimsParameter(claimsValues, isEssential));
                                }
                            }
                        });
        return claimsParameters;
    }

    private static Optional<ClaimsValue> claimsValue(JsonNode node) {
        if (node.isTextual()) {
            return Optional.of(ClaimsValue.of(node.textValue()));
        }
        if (node.isNumber()) {
            return Optional.of(ClaimsValue.of(node.numberValue()));
        }
        if (node.booleanValue()) {
            return Optional.of(ClaimsValue.of(node.booleanValue()));
        }
        return Optional.empty();
    }
}
