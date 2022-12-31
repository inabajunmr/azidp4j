package org.azidp4j.springsecuritysample.handler;

import java.time.Instant;
import java.util.List;
import javax.servlet.http.HttpSession;
import org.azidp4j.springsecuritysample.authentication.SelfReportedAuthenticationToken;
import org.azidp4j.springsecuritysample.user.UserStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/login/self-reported")
public class SelfReportedLoginEndpointHandler {

    @Autowired UserDetailsService userDetailsService;

    @Autowired UserStore userStore;

    private static final Logger LOGGER =
            LoggerFactory.getLogger(SelfReportedLoginEndpointHandler.class);

    @GetMapping
    public String form() {
        LOGGER.info(SelfReportedLoginEndpointHandler.class.getName());
        return "self-reported-login";
    }

    @PostMapping
    public String login(HttpSession session, @RequestParam String username) {
        LOGGER.info(SelfReportedLoginEndpointHandler.class.getName());
        UserDetails user;
        try {
            user = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            return "redirect:/login/self-reported?error";
        }
        userStore.find(username).put("auth_time_sec", Instant.now().getEpochSecond());
        SecurityContextHolder.getContext()
                .setAuthentication(new SelfReportedAuthenticationToken(user, List.of()));

        var redirectTo = (SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        if (redirectTo != null) {
            return "redirect:" + redirectTo.getRedirectUrl();
        }
        return "redirect:/";
    }
}
