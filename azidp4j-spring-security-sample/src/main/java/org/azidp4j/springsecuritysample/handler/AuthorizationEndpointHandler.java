package org.azidp4j.springsecuritysample.handler;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.azidp4j.AzIdP;
import org.azidp4j.authorize.request.AuthorizationRequest;
import org.azidp4j.authorize.response.AdditionalPage;
import org.azidp4j.authorize.response.ErrorPage;
import org.azidp4j.springsecuritysample.authentication.AcrValue;
import org.azidp4j.springsecuritysample.claims.ClaimsParameterParser;
import org.azidp4j.springsecuritysample.claims.ClaimsValue;
import org.azidp4j.springsecuritysample.consent.InMemoryUserConsentStore;
import org.azidp4j.springsecuritysample.user.UserStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.savedrequest.SimpleSavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
public class AuthorizationEndpointHandler {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(AuthorizationEndpointHandler.class);

    @Autowired AzIdP azIdP;

    @Autowired InMemoryUserConsentStore inMemoryUserConsentStore;

    @Autowired UserStore userStore;

    @Autowired LocaleResolver localeResolver;

    @Autowired MessageSource messages;

    /**
     * @see <a
     *     href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.1">https://datatracker.ietf.org/doc/html/rfc6749#section-3.1</a>
     * @see <a
     *     href="https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint">https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint</a>
     * @see <a
     *     href="https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest">https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest</a>
     */
    @GetMapping("/authorize")
    public String authorizationEndpoint(
            @RequestParam Map<String, String> params,
            HttpServletRequest req,
            HttpServletResponse res) {
        LOGGER.info(AuthorizationEndpointHandler.class.getName());

        // When user is unauthenticated, azidp4j accepts null as authenticatedUserName.
        // In that case, azidp4j requires login page or error.
        String authenticatedUserName = null;
        AcrValue userAcr = null;
        if (req.getUserPrincipal() != null) {
            authenticatedUserName = req.getUserPrincipal().getName();
            userAcr =
                    AuthenticationAcrMapper.map(
                            SecurityContextHolder.getContext().getAuthentication());
        }

        // Consented scope management is out of scope from azidp.
        var clientId = params.getOrDefault("client_id", null);
        var consentedScopes =
                inMemoryUserConsentStore.getUserConsents(authenticatedUserName, clientId);

        // Construct AuthorizationRequest for azidp4j
        var authzReq =
                new AuthorizationRequest(
                        authenticatedUserName,
                        authenticatedUserName != null
                                ? (long) userStore.find(authenticatedUserName).get("auth_time_sec")
                                : null,
                        consentedScopes,
                        params);
        if (userAcr != null) {
            authzReq.setAuthenticatedUserAcr(userAcr.value);
        }

        // Authorization Request
        var response = azIdP.authorize(authzReq);
        // azidp4j responses what authorization should do next.
        switch (response.next) {
            case redirect -> {
                var redirect = response.redirect();
                if (!response.redirect().isSuccessResponse()) {
                    return "redirect:" + redirect.createRedirectTo().toString();
                }

                // handle acr claims
                var claims = ClaimsParameterParser.parse(response.authorizationRequest().claims);
                var claimsParameterAcr = claims.fromIdToken("acr");
                if (claimsParameterAcr.isEmpty()) {
                    // no acr claims
                    return "redirect:" + redirect.createRedirectTo().toString();
                }
                if (claimsParameterAcr.get().contains(ClaimsValue.of(userAcr.value))) {
                    // userAcr satisfy claims parameter
                    return "redirect:" + redirect.createRedirectTo().toString();
                }

                // Save authorization request
                var queryParamsForSavedAuthorizationRequest =
                        new LinkedMultiValueMap<String, String>();
                authzReq.queryParameters()
                        .forEach(
                                (k, v) ->
                                        queryParamsForSavedAuthorizationRequest.add(
                                                k, URLEncoder.encode(v, StandardCharsets.UTF_8)));
                req.getSession()
                        .setAttribute(
                                "SPRING_SECURITY_SAVED_REQUEST",
                                new SimpleSavedRequest(
                                        UriComponentsBuilder.fromPath("/authorize")
                                                .queryParams(
                                                        queryParamsForSavedAuthorizationRequest)
                                                .build()
                                                .toUriString()));

                // userAcr doesn't satisfy claims parameter acr so redirect to login page
                var requiredAcrClaims =
                        claimsParameterAcr.get().getValues().stream()
                                .filter(ClaimsValue::isText)
                                .map(ClaimsValue::asText)
                                .toList();

                if (requiredAcrClaims.contains(AcrValue.self_reported.value)) {
                    return "redirect:" + AcrValue.self_reported.path;
                }
                if (requiredAcrClaims.contains(AcrValue.pwd.value)) {
                    return "redirect:" + AcrValue.self_reported.path;
                }
                // claims parameter acr values are not supported at the application
                if (claimsParameterAcr.get().isEssential()) {
                    // unsupported acr is essential so error
                    var message =
                            messages.getMessage(
                                    "exception.authorization_request.invalid",
                                    new String[] {"unsupported acr claim"},
                                    res.getLocale());
                    req.getSession()
                            .setAttribute(
                                    WebAttributes.AUTHENTICATION_EXCEPTION,
                                    new InnerAuthenticationException(message));
                    return "redirect:/login?error";
                }
                return "redirect:" + redirect.createRedirectTo().toString();
            }
            case errorPage -> {
                // Error but can't redirect as authorization response.
                // ex. redirect_uri is not allowed.
                return errorPage(req, res, response.errorPage());
            }
            case additionalPage -> {
                // When authorization request processing needs additional action.
                // ex. user authentication or request consent.
                return additionalPage(
                        req,
                        res,
                        authzReq,
                        response.additionalPage(),
                        response.authorizationRequest().claims);
            }
            default -> throw new AssertionError();
        }
    }

    private String additionalPage(
            HttpServletRequest req,
            HttpServletResponse res,
            AuthorizationRequest authzReq,
            AdditionalPage additionalPage,
            String claims) {

        var uiLocale = uiLocales(additionalPage.uiLocales);
        localeResolver.setLocale(req, res, uiLocale);
        switch (additionalPage.prompt) {
            case login -> {
                var queryParamsForSavedAuthorizationRequest =
                        new LinkedMultiValueMap<String, String>();
                // After user login, redirect to authorization once again.
                // So server needs to save authorization request.
                // But if request has prompt=login, same authorization request repeatedly requires
                // login so
                // remove the prompt parameter.
                authzReq.removePrompt("login")
                        .queryParameters()
                        .forEach(
                                (k, v) ->
                                        queryParamsForSavedAuthorizationRequest.add(
                                                k, URLEncoder.encode(v, StandardCharsets.UTF_8)));

                // Save authorization request without prompt=login in session.
                req.getSession()
                        .setAttribute(
                                "SPRING_SECURITY_SAVED_REQUEST",
                                new SimpleSavedRequest(
                                        UriComponentsBuilder.fromPath("/authorize")
                                                .queryParams(
                                                        queryParamsForSavedAuthorizationRequest)
                                                .build()
                                                .toUriString()));
                if (additionalPage.loginHint != null) {
                    req.getSession()
                            .setAttribute("EXPECTED_USER_SUBJECT", additionalPage.loginHint);
                }
                if (additionalPage.expectedUserSubject != null) {
                    req.getSession()
                            .setAttribute(
                                    "EXPECTED_USER_SUBJECT", additionalPage.expectedUserSubject);
                }

                // handle acr claims
                var acrClaim = ClaimsParameterParser.parse(claims).fromIdToken("acr");
                if (acrClaim.isPresent()) {
                    for (var claimsParameterAcrValue : acrClaim.get().getValues()) {
                        if (!claimsParameterAcrValue.isText()) {
                            continue;
                        }
                        if (!additionalPage.acrValues.isEmpty()
                                && !additionalPage.acrValues.contains(
                                        claimsParameterAcrValue.asText())) {
                            // The acrValue doesn't satisfy acr_values parameter so ignore it
                            continue;
                        }
                        if (AcrValue.self_reported.value.equals(claimsParameterAcrValue.asText())) {
                            return "redirect:" + AcrValue.self_reported.path;
                        }
                        if (AcrValue.self_reported.value.equals(claimsParameterAcrValue.asText())) {
                            return "redirect:" + AcrValue.pwd.path;
                        }
                    }
                    // the required(essential) acr value is not supported
                    if (acrClaim.get().isEssential()) {
                        var message =
                                messages.getMessage(
                                        "exception.authorization_request.invalid",
                                        new String[] {"unsupported acr claim"},
                                        uiLocale);
                        req.getSession()
                                .setAttribute(
                                        WebAttributes.AUTHENTICATION_EXCEPTION,
                                        new InnerAuthenticationException(message));
                        return "redirect:/login?error";
                    }
                }

                // handle acr_values parameter
                if (!additionalPage.acrValues.isEmpty()
                        && additionalPage.acrValues.contains(AcrValue.self_reported.value)) {
                    // if acr_values parameter required self-reported login
                    return "redirect:" + AcrValue.self_reported.path;
                }
                // Redirect to Login page.
                return "redirect:" + AcrValue.pwd.path;
            }
            case consent -> {
                // After user consent, redirect to authorization once again.
                // So server needs to save authorization request.
                // But if request has prompt=consent, same authorization request repeatedly requires
                // login so
                // remove the prompt parameter.
                var queryParamsForSavedAuthorizationRequest =
                        new LinkedMultiValueMap<String, String>();
                authzReq.removePrompt("consent")
                        .queryParameters()
                        .forEach(
                                (k, v) ->
                                        queryParamsForSavedAuthorizationRequest.add(
                                                k, URLEncoder.encode(v, StandardCharsets.UTF_8)));

                // Save authorization request without prompt=consent in session.
                req.getSession()
                        .setAttribute(
                                "SPRING_SECURITY_SAVED_REQUEST",
                                new SimpleSavedRequest(
                                        UriComponentsBuilder.fromPath("/authorize")
                                                .queryParams(
                                                        queryParamsForSavedAuthorizationRequest)
                                                .build()
                                                .toUriString()));

                // Redirect to consent page.
                return "redirect:"
                        + UriComponentsBuilder.fromPath("/consent")
                                .queryParam(
                                        "scope",
                                        URLEncoder.encode(
                                                additionalPage.scope, StandardCharsets.UTF_8))
                                .queryParam(
                                        "clientId",
                                        URLEncoder.encode(
                                                additionalPage.clientId, StandardCharsets.UTF_8))
                                .build();
            }
            case select_account -> throw new IllegalArgumentException(
                    "This sample doesn't support select_account");
            default -> throw new AssertionError();
        }
    }

    private String errorPage(HttpServletRequest req, HttpServletResponse res, ErrorPage errorPage) {
        var session = req.getSession();
        var uiLocale = uiLocales(errorPage.uiLocales);
        localeResolver.setLocale(req, res, uiLocale);
        var message =
                messages.getMessage(
                        "exception.authorization_request.invalid",
                        new String[] {errorPage.errorType.name()},
                        uiLocale);
        session.setAttribute(
                WebAttributes.AUTHENTICATION_EXCEPTION, new InnerAuthenticationException(message));
        return "redirect:/login?error";
    }

    private static Locale uiLocales(List<String> uiLocales) {
        for (String uiLocale : uiLocales) {
            if (uiLocale.startsWith("ja")) {
                return Locale.JAPANESE;
            }
            if (uiLocale.startsWith("en")) {
                return Locale.ENGLISH;
            }
        }
        return Locale.ENGLISH;
    }
}

class InnerAuthenticationException extends AuthenticationException {

    public InnerAuthenticationException(String msg) {
        super(msg);
    }
}
