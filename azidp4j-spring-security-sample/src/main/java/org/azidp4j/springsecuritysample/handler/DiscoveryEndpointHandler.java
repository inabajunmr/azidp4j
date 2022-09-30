package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import org.azidp4j.AzIdP;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DiscoveryEndpointHandler {

    @Autowired AzIdP azIdP;

    @GetMapping("/.well-known/openid-configuration")
    public Map<String, Object> discover() {
        return azIdP.discovery();
    }
}
