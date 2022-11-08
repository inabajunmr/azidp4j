package org.azidp4j.springsecuritysample;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.function.Function;
import org.azidp4j.client.SigningAlgorithm;

public class IdTokenKidSupplier implements Function<SigningAlgorithm, String> {

    private final JWKSet jwkSet;

    public IdTokenKidSupplier(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    @Override
    public String apply(SigningAlgorithm signingAlgorithm) {
        var key =
                jwkSet.getKeys().stream()
                        .filter(k -> k.getAlgorithm().getName().equals(signingAlgorithm.name()))
                        .findAny();
        return key.orElseThrow(AssertionError::new).getKeyID();
    }
}
