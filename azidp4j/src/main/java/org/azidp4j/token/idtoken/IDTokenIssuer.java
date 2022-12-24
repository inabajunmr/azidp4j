package org.azidp4j.token.idtoken;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.PlainObject;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.SigningAlgorithm;
import org.azidp4j.jwt.JWSIssuer;
import org.azidp4j.util.MapUtil;

public class IDTokenIssuer {

    private final AzIdPConfig config;

    private final JWSIssuer jwsIssuer;

    private final Function<SigningAlgorithm, String> kidSupplier;

    private final IDTokenClaimsAssembler idTokenClaimsAssembler;

    public IDTokenIssuer(
            AzIdPConfig config,
            JWKSet jwkSet,
            Function<SigningAlgorithm, String> kidSupplier,
            IDTokenClaimsAssembler idTokenClaimsAssembler) {
        this.config = config;
        this.jwsIssuer = new JWSIssuer(jwkSet);
        this.kidSupplier = kidSupplier;
        this.idTokenClaimsAssembler = idTokenClaimsAssembler;
    }

    public JOSEObject issue(
            String sub,
            String clientId,
            Long authTime,
            String nonce,
            String accessToken,
            String authorizationCode,
            SigningAlgorithm alg,
            String scope,
            boolean accessTokenWillIssued) {
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
        if (idTokenClaimsAssembler != null && !accessTokenWillIssued) {
            var profiles =
                    idTokenClaimsAssembler.assemble(
                            sub,
                            Arrays.stream(scope.split(" "))
                                    .map(String::trim)
                                    .collect(Collectors.toSet()));
            if (profiles != null) {
                // merge
                var mutableProfiles = new HashMap<>(profiles);
                mutableProfiles.putAll(claims);
                claims = mutableProfiles;
            }
        }
        if (alg.equals(SigningAlgorithm.none)) {
            return new PlainObject(new Payload(claims));
        }
        return jwsIssuer.issue(kidSupplier.apply(alg), null, claims);
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
