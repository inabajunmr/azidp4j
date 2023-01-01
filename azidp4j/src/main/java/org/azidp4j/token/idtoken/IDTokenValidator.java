package org.azidp4j.token.idtoken;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.text.ParseException;
import java.util.Objects;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.Client;

public class IDTokenValidator {

    private final AzIdPConfig config;

    private final JWKSet jwks;

    public IDTokenValidator(AzIdPConfig config, JWKSet jwkSet) {
        this.config = config;
        this.jwks = jwkSet;
    }

    /**
     * Validate ID Token but ignores exp/iat/nonce/acr/auth_time claims.
     *
     * @param idToken ID Token
     * @param client authorization request client_id
     * @return ID Token
     */
    public JOSEObject validateForIdTokenHint(String idToken, Client client) {

        // verify sign
        JWSObject parsedIdToken;
        try {
            parsedIdToken = JWSObject.parse(idToken);
        } catch (ParseException e) {
            throw new InvalidIDTokenException(e.getMessage(), e);
        }
        var jwk = jwks.getKeyByKeyId(parsedIdToken.getHeader().getKeyID());
        if (jwk == null) {
            throw new InvalidIDTokenException(
                    "Key:" + parsedIdToken.getHeader().getKeyID() + " is not found");
        }

        JWSVerifier verifier = null;
        try {

            if (jwk instanceof RSAKey key) {
                verifier = new RSASSAVerifier(key);
            }
            if (jwk instanceof ECKey key) {
                verifier = new ECDSAVerifier(key);
            }
            if (verifier == null) {
                throw new InvalidIDTokenException("Unsupported alg");
            }
            if (!parsedIdToken.verify(verifier)) {
                throw new InvalidIDTokenException("Failed to verify signature");
            }
        } catch (JOSEException e) {
            throw new InvalidIDTokenException(e.getMessage(), e);
        }

        var payload = parsedIdToken.getPayload().toJSONObject();

        if (!Objects.equals(config.issuer, payload.get("iss"))) {
            throw new InvalidIDTokenException("Issuer unmatched");
        }

        if (!Objects.equals(client.clientId, payload.get("aud"))) {
            throw new InvalidIDTokenException("Audience unmatched");
        }

        if (!Objects.equals(client.clientId, payload.get("azp"))) {
            throw new InvalidIDTokenException("Authorized Party unmatched");
        }

        if (client.idTokenSignedResponseAlg == null) {
            throw new InvalidIDTokenException("Client doesn't have idTokenSignedResponseAlg");
        }

        if (!Objects.equals(
                client.idTokenSignedResponseAlg.name(),
                parsedIdToken.getHeader().getAlgorithm().getName())) {
            throw new InvalidIDTokenException(
                    "Client doesn't support " + parsedIdToken.getHeader().getAlgorithm().getName());
        }

        return parsedIdToken;
    }
}
