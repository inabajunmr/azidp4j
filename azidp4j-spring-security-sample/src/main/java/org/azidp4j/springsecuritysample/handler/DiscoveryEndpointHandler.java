package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import org.azidp4j.AzIdP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DiscoveryEndpointHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(DiscoveryEndpointHandler.class);

    @Autowired AzIdP azIdP;

    @GetMapping("/.well-known/openid-configuration")
    public Map<String, Object> discover() {
        LOGGER.info(DiscoveryEndpointHandler.class.getName());
        return azIdP.discovery();
    }
}
