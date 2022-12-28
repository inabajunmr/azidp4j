package org.azidp4j.authorize.parser;

import java.net.URI;
import org.azidp4j.authorize.request.Display;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.response.AuthorizationResponse;
import org.azidp4j.util.MapUtil;

public class DisplayParser {
    public static ParseResult<Display> parse(
            String display,
            URI redirectUri,
            ResponseMode parsedResponseMode,
            InternalAuthorizationRequest authorizationRequest) {
        if (display != null) {
            try {
                return ParseResult.of(Display.of(display));
            } catch (IllegalArgumentException e) {
                return ParseResult.error(
                        AuthorizationResponse.redirect(
                                redirectUri,
                                MapUtil.nullRemovedStringMap(
                                        "error",
                                        "invalid_request",
                                        "state",
                                        authorizationRequest.state),
                                parsedResponseMode,
                                false,
                                "display parse error",
                                authorizationRequest));
            }
        } else {
            return ParseResult.of(Display.page);
        }
    }
}
