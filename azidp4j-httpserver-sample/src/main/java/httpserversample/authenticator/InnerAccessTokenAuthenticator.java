package httpserversample.authenticator;

import com.sun.net.httpserver.Authenticator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;
import org.azidp4j.token.accesstoken.AccessTokenService;

import java.util.Arrays;

public class InnerAccessTokenAuthenticator extends Authenticator {

    private final AccessTokenService accessTokenService;

    public InnerAccessTokenAuthenticator(AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
    }

    @Override
    public Result authenticate(HttpExchange httpExchange) {
        var authorization = httpExchange.getRequestHeaders().get("Authorization").get(0);
        if (!authorization.startsWith("Bearer ")) {
            return new Failure(403);
        }
        var token = accessTokenService.introspect(authorization.replaceAll("^Bearer ", ""));
        if(token.isPresent()) {
            if(Arrays.asList(token.get().getScope().split(" ")).contains("default")){
                return new Success(
                        new HttpPrincipal(
                                token.get().getSub(),
                                "client registration"));
            }
        }
        return new Failure(403);
    }
}
