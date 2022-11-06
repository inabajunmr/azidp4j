package org.azidp4j.token;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.function.Function;
import org.azidp4j.client.SigningAlgorithm;

public class SampleIdTokenKidSupplier implements Function<SigningAlgorithm, String> {

    private final JWKSet jwkSet;

    public SampleIdTokenKidSupplier(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    @Override
    public String apply(SigningAlgorithm signingAlgorithm) {
        if (signingAlgorithm.equals(SigningAlgorithm.none)) {
            return null;
        }
        return jwkSet.getKeys().stream()
                .filter(k -> k.getAlgorithm().getName().equals(signingAlgorithm.name()))
                .findAny()
                .get()
                .getKeyID();
    }
}
