package httpserversample;

import com.nimbusds.jose.JOSEException;

import java.util.Map;
import java.util.Set;

import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.request.ClientRequest;
import org.azidp4j.client.GrantType;

public class SampleAzRunner {
    public static void main(String[] args) throws JOSEException {
        var az = new SampleAz();
        var clientRegistrationRequest = new ClientRequest(
                Map.of("grant_type",  Set.of(
                GrantType.authorization_code.name(),
                GrantType.client_credentials.name(),
                GrantType.implicit.name(),
                GrantType.password.name(),
                GrantType.refresh_token.name()),
                "scope","rs:scope1 rs:scope2 openid",
                "redirect_uris", Set.of("http://example.com"),
                "response_types", Set.of(ResponseType.code.name(), ResponseType.token.name())
                ));

        try {
            var client = az.azIdP.registerClient(clientRegistrationRequest);
            var clientId = client.body.get("client_id");
            var clientSecret = client.body.get("client_secret");
            System.out.println("client_id:" + clientId + " client_secret:" + clientSecret);
            System.out.println(
                    "http://localhost:8080/authorize?response_type=code&client_id="
                            + clientId
                            + "&redirect_uri=http://example.com&scope=openid");
            System.out.println(
                    "curl -X POST -u "
                            + clientId
                            + ":"
                            + clientSecret
                            + " -d 'grant_type=authorization_code' -d"
                            + " 'redirect_uri=http://example.com' -d 'code=xxx'"
                            + " http://localhost:8080/token");
            az.start(8080);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
