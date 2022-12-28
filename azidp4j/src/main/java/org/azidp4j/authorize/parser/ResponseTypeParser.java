package org.azidp4j.authorize.parser;

import java.util.List;
import java.util.Set;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.authorize.response.AuthorizationErrorTypeWithoutRedirect;
import org.azidp4j.authorize.response.AuthorizationResponse;

/** Authorization Request Parser for code_challenge and code_challenge_method */
public class ResponseTypeParser {

    public static ParseResult<Set<ResponseType>> parse(
            String responseType,
            List<String> locales,
            InternalAuthorizationRequest authorizationRequest,
            Set<Set<ResponseType>> responseTypeSupported) {
        Set<ResponseType> responseTypes;
        try {
            responseTypes = ResponseType.parse(responseType);
        } catch (IllegalArgumentException e) {
            return ParseResult.error(
                    AuthorizationResponse.errorPage(
                            AuthorizationErrorTypeWithoutRedirect.invalid_response_type,
                            locales,
                            "response_type parse error",
                            authorizationRequest));
        }
        if (responseTypes.isEmpty()) {
            return ParseResult.error(
                    AuthorizationResponse.errorPage(
                            AuthorizationErrorTypeWithoutRedirect.invalid_response_type,
                            locales,
                            "response_type parse error",
                            authorizationRequest));
        }
        if (!responseTypeSupported.contains(responseTypes)) {
            return ParseResult.error(
                    AuthorizationResponse.errorPage(
                            AuthorizationErrorTypeWithoutRedirect.unsupported_response_type,
                            locales,
                            "azidp doesn't support response_type",
                            authorizationRequest));
        }
        return ParseResult.of(ResponseType.parse(responseType));
    }
}
