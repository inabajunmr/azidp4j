package httpserversample.handler;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;

public abstract class AzIdpHttpHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) {
        try {
            System.out.println(this.getClass().getSimpleName());
            System.out.println(exchange.getRequestMethod());
            System.out.println(exchange.getRequestURI());
            this.process(exchange);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    public abstract void process(HttpExchange exchange) throws IOException;
}
