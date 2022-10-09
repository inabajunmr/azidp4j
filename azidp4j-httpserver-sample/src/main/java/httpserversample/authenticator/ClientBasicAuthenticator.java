package httpserversample.authenticator;

import com.sun.net.httpserver.BasicAuthenticator;
import org.azidp4j.client.ClientStore;

public class ClientBasicAuthenticator extends BasicAuthenticator {

    private final ClientStore clientStore;

    public ClientBasicAuthenticator(ClientStore clientStore) {
        super("client");
        this.clientStore = clientStore;
    }

    @Override
    public boolean checkCredentials(String clientId, String secret) {
        var client = clientStore.find(clientId);
        if (!client.isPresent()) {
            return false;
        }
        return client.get().clientSecret.equals(secret);
    }
}
