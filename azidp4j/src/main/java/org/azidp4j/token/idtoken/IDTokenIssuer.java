package org.azidp4j.token.idtoken;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.SigningAlgorithm;
import org.azidp4j.jwt.JWSIssuer;
import org.azidp4j.util.MapUtil;

public class IDTokenIssuer {

    private final AzIdPConfig config;

    private final JWSIssuer jwsIssuer;

    public IDTokenIssuer(AzIdPConfig config, JWKSet jwkSet) {
        this.config = config;
        this.jwsIssuer = new JWSIssuer(jwkSet);
    }

    public JOSEObject issue(
            String sub,
            String clientId,
            Long authTime,
            String nonce,
            String accessToken,
            String authorizationCode,
            SigningAlgorithm alg) {
        var jti = UUID.randomUUID().toString();
        var atHash = accessToken != null ? calculateXHash(accessToken) : null;
        var cHash = authorizationCode != null ? calculateXHash(authorizationCode) : null;
        Map<String, Object> claims =
                MapUtil.nullRemovedMap(
                        "iss",
                        config.issuer,
                        "sub",
                        sub,
                        "aud",
                        clientId,
                        "exp",
                        Instant.now().getEpochSecond() + config.idTokenExpiration.toSeconds(),
                        "iat",
                        Instant.now().getEpochSecond(),
                        "jti",
                        jti,
                        "auth_time",
                        authTime,
                        "nonce",
                        nonce,
                        "azp",
                        clientId,
                        "at_hash",
                        atHash,
                        "c_hash",
                        cHash);
        return jwsIssuer.issue(alg, claims);
    }

    private String calculateXHash(String token) {
        try {
            var sha256 = MessageDigest.getInstance("SHA-256");
            var hash = sha256.digest(token.getBytes());
            return Base64URL.encode(Arrays.copyOfRange(hash, 0, hash.length / 2)).toString();
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }
}
