package org.azidp4j.authorize.response;

public enum AuthorizationErrorTypeWithoutRedirect {
    invalid_response_type,
    invalid_response_mode,
    unsupported_response_type,
    unsupported_response_mode,
    client_id_required,
    client_not_found,
    redirect_uri_not_allowed,
    invalid_redirect_uri
}
