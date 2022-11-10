package org.azidp4j.springsecuritysample;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.function.Function;
import org.azidp4j.client.SigningAlgorithm;

/** This is used to select key for ID Token signing. */
public class IdTokenKidSupplier implements Function<SigningAlgorithm, String> {

    private final JWKSet jwkSet;

    public IdTokenKidSupplier(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    @Override
    public String apply(SigningAlgorithm signingAlgorithm) {
        // Using any key that matches algorithm.
        var key =
                jwkSet.getKeys().stream()
                        .filter(k -> k.getAlgorithm().getName().equals(signingAlgorithm.name()))
                        .findAny();
        return key.orElseThrow(AssertionError::new).getKeyID();
    }
}
