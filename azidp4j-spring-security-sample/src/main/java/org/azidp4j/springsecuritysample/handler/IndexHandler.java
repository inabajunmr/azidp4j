package org.azidp4j.springsecuritysample.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(IndexHandler.class);

    @GetMapping("/")
    public String index() {
        LOGGER.info(IndexHandler.class.getName());
        return "sample";
    }
}
