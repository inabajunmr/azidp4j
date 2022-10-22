package org.azidp4j.springsecuritysample.handler;

import java.util.Arrays;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.azidp4j.springsecuritysample.consent.InMemoryUserConsentStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/consent")
public class ConsentHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConsentHandler.class);

    @Autowired InMemoryUserConsentStore consentStore;

    @GetMapping
    public String form(Model model, @RequestParam String scope, @RequestParam String clientId) {
        LOGGER.info(ConsentHandler.class.getName());
        var scopes = scope.split(" ");
        model.addAttribute("clientId", clientId);
        model.addAttribute("scopes", scopes);
        return "consent";
    }

    @PostMapping
    public String consent(
            HttpSession session,
            HttpServletRequest req,
            @RequestParam String scope,
            @RequestParam String clientId) {
        LOGGER.info(ConsentHandler.class.getName());
        consentStore.consent(
                req.getUserPrincipal().getName(),
                clientId,
                Arrays.stream(scope.split(" ")).collect(Collectors.toSet()));
        var redirectTo = (SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        return "redirect:" + redirectTo.getRedirectUrl();
    }
}
