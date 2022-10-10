package org.azidp4j.springsecuritysample.handler;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.AzIdP;
import org.azidp4j.authorize.AuthorizationResponse;
import org.azidp4j.authorize.request.AuthorizationRequest;
import org.azidp4j.springsecuritysample.consent.InMemoryUserConsentStore;
import org.azidp4j.springsecuritysample.user.UserStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.savedrequest.SimpleSavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
public class AuthorizationEndpointHandler {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(AuthorizationEndpointHandler.class);

    @Autowired AzIdP azIdP;

    @Autowired InMemoryUserConsentStore inMemoryUserConsentStore;

    @Autowired UserStore userStore;

    @GetMapping("/authorize")
    public String authorizationEndpoint(
            @RequestParam Map<String, String> params, HttpServletRequest req) {
        LOGGER.info(AuthorizationEndpointHandler.class.getName());
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
                        authenticatedUserName != null
                                ? (long) userStore.find(authenticatedUserName).get("auth_time_sec")
                                : null,
                        consentedScopes,
                        params);
        var response = azIdP.authorize(authzReq);
        switch (response.next) {
            case redirect:
                {
                    return "redirect:" + response.redirect.redirectTo;
                }
            case errorPage:
                {
                    return errorPage(req, response);
                }
            case additionalPage:
                {
                    return additionalPage(req, authzReq, response);
                }
            default:
                {
                    throw new AssertionError();
                }
        }
    }

    private static String additionalPage(
            HttpServletRequest req, AuthorizationRequest authzReq, AuthorizationResponse response) {
        switch (response.additionalPage.prompt) {
            case login -> {
                var session = req.getSession();
                var map = new LinkedMultiValueMap<String, String>();
                authzReq.removePrompt("login")
                        .queryParameters()
                        .forEach(
                                (k, v) -> map.add(k, URLEncoder.encode(v, StandardCharsets.UTF_8)));
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
                authzReq.removePrompt("consent")
                        .queryParameters()
                        .forEach(
                                (k, v) -> map.add(k, URLEncoder.encode(v, StandardCharsets.UTF_8)));
                session.setAttribute(
                        "SPRING_SECURITY_SAVED_REQUEST",
                        new SimpleSavedRequest(
                                UriComponentsBuilder.fromPath("/authorize")
                                        .queryParams(map)
                                        .build()
                                        .toUriString()));
                UriComponentsBuilder.fromPath("/consent")
                        .queryParam("scope", authzReq.queryParameters().get("scope"))
                        .build();
                return "redirect:"
                        + UriComponentsBuilder.fromPath("/consent")
                                // TODO not good interface
                                .queryParam(
                                        "scope",
                                        URLEncoder.encode(
                                                authzReq.queryParameters().get("scope"),
                                                StandardCharsets.UTF_8))
                                .queryParam(
                                        "clientId",
                                        URLEncoder.encode(
                                                authzReq.queryParameters().get("client_id"),
                                                StandardCharsets.UTF_8))
                                .build();
            }
            case select_account -> {
                throw new AssertionError();
            }
            default -> {
                throw new AssertionError();
            }
        }
    }

    private static String errorPage(HttpServletRequest req, AuthorizationResponse response) {
        var session = req.getSession();
        switch (response.errorPage.errorType) {
            case invalid_response_type -> session.setAttribute(
                    WebAttributes.AUTHENTICATION_EXCEPTION,
                    new InnerAuthenticationException(
                            "RP send wrong authorization request. debug:" + " no_response_type"));
            default -> session.setAttribute(
                    WebAttributes.AUTHENTICATION_EXCEPTION,
                    new InnerAuthenticationException(
                            "RP send wrong authorization request. debug: "
                                    + response.errorPage.errorType.name()));
        }
        return "redirect:/login?error";
    }
}

class InnerAuthenticationException extends AuthenticationException {

    public InnerAuthenticationException(String msg) {
        super(msg);
    }
}
