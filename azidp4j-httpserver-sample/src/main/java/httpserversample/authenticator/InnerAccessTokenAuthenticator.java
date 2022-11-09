package httpserversample.authenticator;

import com.sun.net.httpserver.Authenticator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;
import org.azidp4j.AzIdP;
import org.azidp4j.introspection.request.IntrospectionRequest;

import java.util.Arrays;
import java.util.Map;

public class InnerAccessTokenAuthenticator extends Authenticator {

    private final AzIdP azIdP;

    public InnerAccessTokenAuthenticator(AzIdP azIdP) {
        this.azIdP = azIdP;
    }

    @Override
    public Result authenticate(HttpExchange httpExchange) {
        var authorization = httpExchange.getRequestHeaders().get("Authorization").get(0);
        if (!authorization.startsWith("Bearer ")) {
            return new Failure(403);
        }
        var res = azIdP.introspect(new IntrospectionRequest(
                Map.of("token", authorization.replaceAll("^Bearer ", ""), "token_type_hint", "access_token")));
        if (res.status != 200) {
            return new Failure(403);
        }
        if (res.body.get("active") instanceof Boolean active && active) {
            if(Arrays.asList(res.body.get("scope").toString().split(" ")).contains("default")) {
                return new Success(
                        new HttpPrincipal(
                                res.body.get("sub").toString(),
                                "client registration"));
            }
        }
        return new Failure(403);
    }
}
