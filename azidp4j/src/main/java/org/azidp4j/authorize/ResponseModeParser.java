package org.azidp4j.authorize;

import java.util.List;
import java.util.Set;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.authorize.response.AuthorizationErrorTypeWithoutRedirect;
import org.azidp4j.authorize.response.AuthorizationResponse;

public class ResponseModeParser {

    public static ParseResult<ResponseMode> parse(
            String responseMode,
            Set<ResponseType> parsedResponseType,
            Set<ResponseMode> responseModesSupported,
            List<String> locales,
            InternalAuthorizationRequest authorizationRequest) {

        ResponseMode parsedResponseMode;
        try {
            parsedResponseMode = ResponseMode.of(responseMode, parsedResponseType);
        } catch (IllegalArgumentException e) {
            return ParseResult.error(
                    AuthorizationResponse.errorPage(
                            AuthorizationErrorTypeWithoutRedirect.invalid_response_mode,
                            locales,
                            "response_mode parse error",
                            authorizationRequest));
        }
        if (!responseModesSupported.contains(parsedResponseMode)) {
            return ParseResult.error(
                    AuthorizationResponse.errorPage(
                            AuthorizationErrorTypeWithoutRedirect.unsupported_response_mode,
                            locales,
                            "azidp doesn't support response_mode",
                            authorizationRequest));
        }

        return ParseResult.of(parsedResponseMode);
    }
}
