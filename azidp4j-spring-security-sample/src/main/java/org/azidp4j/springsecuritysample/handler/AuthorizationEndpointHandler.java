package org.azidp4j.springsecuritysample.handler;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.azidp4j.AzIdP;
import org.azidp4j.authorize.AuthorizationRequest;
import org.azidp4j.springsecuritysample.consent.InMemoryUserConsentStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.savedrequest.SimpleSavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
public class AuthorizationEndpointHandler {

    @Autowired AzIdP azIdP;

    @Autowired InMemoryUserConsentStore inMemoryUserConsentStore;

    @GetMapping("/authorize")
    public String authorizationEndpoint(
            @RequestParam Map<String, String> params,
            HttpServletRequest req,
            HttpServletResponse resp)
            throws IOException {
        String authenticatedUserName = null;
        if (req.getUserPrincipal() != null) {
            authenticatedUserName = req.getUserPrincipal().getName();
        }
        var clientId = params.getOrDefault("client_id", null);
        var consentedScopes =
                inMemoryUserConsentStore.getUserConsents(authenticatedUserName, clientId);
        var authzReq =
                new AuthorizationRequest(
                        authenticatedUserName,
                        Instant.now().getEpochSecond(),
                        consentedScopes,
                        params);
        var response = azIdP.authorize(authzReq);
        if (response.additionalPage != null) {
            switch (response.additionalPage) {
                case login -> {
                    var session = req.getSession();
                    var map = new LinkedMultiValueMap<String, String>();
                    authzReq.removePrompt("login").queryParameters().forEach(map::add);
                    session.setAttribute(
                            "SPRING_SECURITY_SAVED_REQUEST",
                            new SimpleSavedRequest(
                                    UriComponentsBuilder.fromPath("/authorize")
                                            .queryParams(map)
                                            .build()
                                            .toUriString()));
                    return "redirect:/login";
                }
                case consent -> {
                    var session = req.getSession();
                    var map = new LinkedMultiValueMap<String, String>();
                    authzReq.removePrompt("consent").queryParameters().forEach(map::add);
                    session.setAttribute(
                            "SPRING_SECURITY_SAVED_REQUEST",
                            new SimpleSavedRequest(
                                    UriComponentsBuilder.fromPath("/authorize")
                                            .queryParams(map)
                                            .build()
                                            .toUriString()));
                    authzReq.removePrompt("consent").queryParameters().forEach(map::add);
                    UriComponentsBuilder.fromPath("/consent")
                            .queryParam("scope", authzReq.queryParameters().get("scope"))
                            .build();
                    return "redirect:"
                            + UriComponentsBuilder.fromPath("/consent")
                                    // TODO not good interface
                                    .queryParam("scope", authzReq.queryParameters().get("scope"))
                                    .queryParam(
                                            "clientId", authzReq.queryParameters().get("client_id"))
                                    .build();
                }
                case select_account -> {
                    resp.sendError(400);
                    return null;
                }
            }
        }
        response.headers().forEach(resp::setHeader);
        resp.setStatus(response.status);
        resp.getWriter().close();

        return null;
    }
}
