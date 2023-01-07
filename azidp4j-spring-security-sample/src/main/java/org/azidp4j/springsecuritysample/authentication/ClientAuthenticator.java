package org.azidp4j.springsecuritysample.authentication;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.client.Client;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.TokenEndpointAuthMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class ClientAuthenticator {

    @Autowired ClientStore clientStore;

    @Value("${endpoint}")
    private String endpoint;

    private final BasicAuthenticationConverter authenticationConverter =
            new BasicAuthenticationConverter();

    /**
     * @see <a
     *     href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.3">https://datatracker.ietf.org/doc/html/rfc6749#section-2.3</a>
     */
    public Optional<Client> authenticateClient(HttpServletRequest request) {
        // client_secret_basic
        {
            var usernamePasswordAuthenticationToken = authenticationConverter.convert(request);
            if (usernamePasswordAuthenticationToken != null) {
                var client = clientStore.find(usernamePasswordAuthenticationToken.getName());
                // if client supports token_endpoint_auth_method=client_secret_basic,
                // verify client secret.
                if (client.isPresent()
                        && client.get()
                                .clientSecret
                                .equals(usernamePasswordAuthenticationToken.getCredentials())
                        && client.get().tokenEndpointAuthMethod
                                == TokenEndpointAuthMethod.client_secret_basic) {
                    return client;
                }
            }
        }

        // client_secret_post
        {
            // ref. https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
            // Alternatively, the authorization server MAY support including the client credentials
            // in
            // the request-body using the following parameters:
            if (request.getMethod().equals("POST")
                    && request.getParameterMap().containsKey("client_id")) {
                var clientId = request.getParameterMap().get("client_id")[0];
                var client = clientStore.find(clientId);

                // if client supports token_endpoint_auth_method=client_secret_post,
                // verify client secret.
                if (client.isPresent()
                        && client.get().tokenEndpointAuthMethod
                                == TokenEndpointAuthMethod.client_secret_post
                        && request.getParameterMap().containsKey("client_secret")) {

                    // verify client secret
                    if (client.get()
                            .clientSecret
                            .equals(request.getParameterMap().get("client_secret")[0])) {
                        return client;
                    }
                }
            }
        }

        // private_key_jwt
        var clientOpt = authenticateByPrivateKeyJWT(request);
        if (clientOpt.isPresent()) {
            return clientOpt;
        }

        return Optional.empty();
    }

    private Optional<Client> authenticateByPrivateKeyJWT(HttpServletRequest request) {

        // private_key_jwt
        var isPrivateKeyJWT =
                request.getMethod().equals("POST")
                        && request.getParameterMap().containsKey("client_assertion")
                        && request.getParameterMap().containsKey("client_assertion_type")
                        && request.getParameterMap()
                                .get("client_assertion_type")[0]
                                .equals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        if (!isPrivateKeyJWT) {
            return Optional.empty();
        }
        // ref. https://www.rfc-editor.org/rfc/rfc7523
        var clientAssertion = request.getParameterMap().get("client_assertion")[0];
        try {
            var assertion = JWSObject.parse(clientAssertion);
            var parsed = assertion.getPayload().toJSONObject();
            var iss = parsed.get("iss");
            var sub = parsed.get("sub");
            if (iss == null || sub == null || !Objects.equals(iss, sub)) {
                return Optional.empty();
            }

            // find client
            var clientOpt = clientStore.find(iss.toString());
            if (clientOpt.isEmpty()) {
                return Optional.empty();
            }

            var client = clientOpt.get();
            if (!Objects.equals(
                    TokenEndpointAuthMethod.private_key_jwt, client.tokenEndpointAuthMethod)) {
                return Optional.empty();
            }

            // aud
            if (!Objects.equals(endpoint + "/token", parsed.get("aud"))) {
                return Optional.empty();
            }

            // exp
            if (parsed.containsKey("exp")) {
                var exp = parsed.get("exp");
                if (exp instanceof Long e) {
                    if (e <= Instant.now().getEpochSecond()) {
                        return Optional.empty();
                    }
                } else {
                    return Optional.empty();
                }
            } else {
                return Optional.empty();
            }

            // nbf
            if (parsed.containsKey("nbf")) {
                var nbf = parsed.get("nbf");
                if (nbf instanceof Long n) {
                    if (n >= Instant.now().getEpochSecond()) {
                        return Optional.empty();
                    }
                }
            }

            // verify signing
            var kid = assertion.getHeader().getKeyID();
            var jwks = client.jwks;
            if (jwks == null && client.jwksUri != null) {
                // fetch jwks from client registered URI
                var jwkUri = client.jwksUri;
                var restTemplate = new RestTemplate();
                var jwksStr = restTemplate.getForObject(jwkUri, String.class);
                jwks = JWKSet.parse(jwksStr);
            }
            if (jwks == null) {
                return Optional.empty();
            }

            var jwk = jwks.getKeyByKeyId(kid);
            if (jwk == null) {
                return Optional.empty();
            }

            JWSVerifier verifier;
            if (jwk instanceof RSAKey rsaKey) {
                verifier = new RSASSAVerifier(rsaKey);
            } else if (jwk instanceof ECKey ecKey) {
                verifier = new ECDSAVerifier(ecKey);
            } else {
                return Optional.empty();
            }
            if (assertion.verify(verifier)) {
                return clientOpt;
            }
            return Optional.empty();
        } catch (ParseException | JOSEException e) {
            // ignore
            return Optional.empty();
        }
    }
}
