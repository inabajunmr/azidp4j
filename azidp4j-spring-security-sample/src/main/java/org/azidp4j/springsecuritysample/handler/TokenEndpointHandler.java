package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenEndpointHandler {

    @RequestMapping("/token")
    public Map tokenEndpoint() {
        // TODO
        return Map.of("test", "test");
    }
}
