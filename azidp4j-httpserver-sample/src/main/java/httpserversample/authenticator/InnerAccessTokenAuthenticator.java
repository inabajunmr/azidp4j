package httpserversample.authenticator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.sun.net.httpserver.Authenticator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;
import org.azidp4j.token.accesstoken.AccessTokenStore;

import java.text.ParseException;
import java.util.Arrays;

public class InnerAccessTokenAuthenticator extends Authenticator {

    private final AccessTokenStore accessTokenStore;

    public InnerAccessTokenAuthenticator(AccessTokenStore accessTokenStore) {
        this.accessTokenStore = accessTokenStore;
    }

    @Override
    public Result authenticate(HttpExchange httpExchange) {
        var authorization = httpExchange.getRequestHeaders().get("Authorization").get(0);
        if (!authorization.startsWith("Bearer ")) {
            return new Failure(403);
        }
        var token = accessTokenStore.find(authorization.replaceAll("^Bearer ", ""));
        if(token.isPresent()) {
            if(Arrays.stream(token.get().getScope().split(" ")).anyMatch(s -> s.equals("default"))){
                return new Success(
                        new HttpPrincipal(
                                token.get().getSub(),
                                "client registration"));
            }
        }
        return new Failure(403);
    }
}
