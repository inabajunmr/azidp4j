package org.azidp4j.authorize.authorizationcode.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;
import org.azidp4j.authorize.authorizationcode.AuthorizationCode;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.request.CodeChallengeMethod;
import org.azidp4j.jwt.JWSIssuer;
import org.azidp4j.util.MapUtil;

public class JwtAuthorizationCodeService implements AuthorizationCodeService {

    private final JWKSet jwkSet;
    private final String issuer;
    private final JWSIssuer jwsIssuer;
    private final Supplier<String> kidSupplier;

    public JwtAuthorizationCodeService(JWKSet jwkSet, String issuer, Supplier<String> kidSupplier) {
        this.jwkSet = jwkSet;
        this.jwsIssuer = new JWSIssuer(jwkSet);
        this.issuer = issuer;
        this.kidSupplier = kidSupplier;
    }

    @Override
    public AuthorizationCode issue(
            String sub,
            String acr,
            String scope,
            String claimsParam,
            String clientId,
            String redirectUri,
            String state,
            Long authTime,
            String nonce,
            String codeChallenge,
            CodeChallengeMethod codeChallengeMethod,
            Long exp) {
        var jti = UUID.randomUUID().toString();
        Map<String, Object> claims =
                MapUtil.nullRemovedMap(
                        "iss",
                        issuer,
                        "sub",
                        sub,
                        "acr",
                        acr,
                        "exp",
                        exp,
                        "jti",
                        jti,
                        "client_id",
                        clientId,
                        "redirect_uri",
                        redirectUri,
                        "scope",
                        scope,
                        "claims",
                        claimsParam,
                        "state",
                        state,
                        "nonce",
                        nonce,
                        "auth_time",
                        authTime,
                        "code_challenge",
                        codeChallenge,
                        "code_challenge_method",
                        codeChallengeMethod);
        var jwt = jwsIssuer.issue(kidSupplier.get(), "ac+jwt", claims).serialize();
        return new AuthorizationCode(
                jwt,
                sub,
                acr,
                scope,
                claimsParam,
                clientId,
                redirectUri,
                state,
                authTime,
                nonce,
                codeChallenge,
                codeChallengeMethod,
                exp);
    }

    @Override
    public Optional<AuthorizationCode> consume(String code) {
        try {
            var jws = JWSObject.parse(code);

            // verify signature
            var key = jwkSet.getKeyByKeyId(jws.getHeader().getKeyID());
            if (key == null) {
                return Optional.empty();
            }
            if (key instanceof ECKey) {
                if (!jws.verify(new ECDSAVerifier((ECKey) key))) {
                    return Optional.empty();
                }
            } else if (key instanceof RSAKey) {
                if (!jws.verify(new RSASSAVerifier((RSAKey) key))) {
                    return Optional.empty();
                }
            } else {
                return Optional.empty();
            }
            if (!Objects.equals(jws.getHeader().toJSONObject().get("typ"), "ac+jwt")) {
                return Optional.empty();
            }
            if (!Objects.equals(jws.getPayload().toJSONObject().get("iss"), issuer)) {
                return Optional.empty();
            }
            if ((Long) jws.getPayload().toJSONObject().get("exp")
                    < Instant.now().getEpochSecond()) {
                return Optional.empty();
            }

            var payload = jws.getPayload().toJSONObject();
            var sub = payload.containsKey("sub") ? (String) payload.get("sub") : null;
            var acr = payload.containsKey("acr") ? (String) payload.get("acr") : null;
            var scope = payload.containsKey("scope") ? (String) payload.get("scope") : null;
            var claims = payload.containsKey("claims") ? (String) payload.get("claims") : null;
            var clientId =
                    payload.containsKey("client_id") ? (String) payload.get("client_id") : null;
            var exp = payload.containsKey("exp") ? (Long) payload.get("exp") : null;
            var redirectUri =
                    payload.containsKey("redirect_uri")
                            ? (String) payload.get("redirect_uri")
                            : null;
            var state = payload.containsKey("state") ? (String) payload.get("state") : null;
            var authTime =
                    payload.containsKey("auth_time") ? (Long) payload.get("auth_time") : null;
            var nonce = payload.containsKey("nonce") ? (String) payload.get("nonce") : null;
            var codeChallenge =
                    payload.containsKey("code_challenge")
                            ? (String) payload.get("code_challenge")
                            : null;
            var codeChallengeMethod =
                    payload.containsKey("code_challenge_method")
                            ? CodeChallengeMethod.of((String) payload.get("code_challenge_method"))
                            : null;
            return Optional.of(
                    new AuthorizationCode(
                            code,
                            sub,
                            acr,
                            scope,
                            claims,
                            clientId,
                            redirectUri,
                            state,
                            authTime,
                            nonce,
                            codeChallenge,
                            codeChallengeMethod,
                            exp));
        } catch (ParseException | JOSEException e) {
            return Optional.empty();
        }
    }
}
