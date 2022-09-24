package org.azidp4j.springsecuritysample.handler;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class TestHandler {

    @GetMapping("/")
    public String index() {
        return "sample";
    }
}
