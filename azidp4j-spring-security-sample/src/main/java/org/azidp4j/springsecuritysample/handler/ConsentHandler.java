package org.azidp4j.springsecuritysample.handler;

import org.azidp4j.springsecuritysample.consent.InMemoryUserConsentStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/consent")
public class ConsentHandler {

    @Autowired InMemoryUserConsentStore consentStore;

    @GetMapping
    public String form() {

        return "consent";
    }

    @PostMapping
    public String consent() {
        return "consent";
    }
    // TODO
}
