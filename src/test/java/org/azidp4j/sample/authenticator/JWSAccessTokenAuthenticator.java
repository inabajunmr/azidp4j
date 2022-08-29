package org.azidp4j.sample.authenticator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.sun.net.httpserver.Authenticator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;
import java.text.ParseException;

public class JWSAccessTokenAuthenticator extends Authenticator {

    private final JWKSet jwkSet;

    public JWSAccessTokenAuthenticator(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    @Override
    public Result authenticate(HttpExchange httpExchange) {
        var authorization = httpExchange.getRequestHeaders().get("Authorization").get(0);
        if (!authorization.startsWith("Bearer ")) {
            return new Failure(403);
        }
        var token = authorization.replaceAll("^Bearer ", "");
        try {
            var parsedToken = JWSObject.parse(token);
            var key =
                    (ECKey)
                            jwkSet.toPublicJWKSet()
                                    .getKeyByKeyId(parsedToken.getHeader().getKeyID());
            if (parsedToken.verify(new ECDSAVerifier(key))) {
                if (parsedToken.getPayload().toJSONObject().get("scope").equals("default")) {
                    return new Success(
                            new HttpPrincipal(
                                    parsedToken.getPayload().toJSONObject().get("sub").toString(),
                                    "client registration"));
                }
            } else {
                return new Failure(403);
            }
        } catch (ParseException | JOSEException e) {
            return new Failure(403);
        }
        return null;
    }
}
