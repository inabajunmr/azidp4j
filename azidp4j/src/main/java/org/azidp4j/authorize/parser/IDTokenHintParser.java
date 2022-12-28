package org.azidp4j.authorize.parser;

import java.net.URI;
import java.util.Objects;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.response.AuthorizationResponse;
import org.azidp4j.client.Client;
import org.azidp4j.token.idtoken.IDTokenValidator;
import org.azidp4j.token.idtoken.InvalidIDTokenException;
import org.azidp4j.util.MapUtil;

public class IDTokenHintParser {

    /**
     * Return subject claim. Not return idTokenHint String.
     */
    public static ParseResult<String> parse(
            String idTokenHint,
            IDTokenValidator idTokenValidator,
            Client client,
            URI redirectUri,
            ResponseMode responseMode,
            InternalAuthorizationRequest authorizationRequest) {
        String idTokenHintSub = null;
        if (idTokenHint != null) {
            try {
                var parsedIdTokenHint =
                        idTokenValidator.validateForIdTokenHint(idTokenHint, client);
                idTokenHintSub =
                        parsedIdTokenHint.getPayload().toJSONObject().get("sub").toString();
            } catch (InvalidIDTokenException e) {
                return ParseResult.error(
                        AuthorizationResponse.redirect(
                                redirectUri,
                                MapUtil.nullRemovedStringMap(
                                        "error",
                                        "invalid_request",
                                        "state",
                                        authorizationRequest.state),
                                responseMode,
                                false,
                                "invalid id_token_hint",
                                authorizationRequest));
            }
        }

        // check authenticated user subject and id_token_hint sub are same.
        if (idTokenHintSub != null && authorizationRequest.authenticatedUserSubject != null) {
            if (!Objects.equals(idTokenHintSub, authorizationRequest.authenticatedUserSubject)) {
                return ParseResult.error(
                        AuthorizationResponse.redirect(
                                redirectUri,
                                MapUtil.nullRemovedStringMap(
                                        "error",
                                        "login_required",
                                        "state",
                                        authorizationRequest.state),
                                responseMode,
                                false,
                                "id_token_hint subject and authenticatedUser subject unmatched",
                                authorizationRequest));
            }
        }

        return ParseResult.of(idTokenHintSub);
    }
}
