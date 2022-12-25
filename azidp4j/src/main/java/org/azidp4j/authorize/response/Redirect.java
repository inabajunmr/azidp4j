package org.azidp4j.authorize.response;

import java.net.URI;
import org.azidp4j.authorize.request.RedirectToSupplier;

public class Redirect {

    private final RedirectToSupplier redirectToSupplier;

    private final boolean isSuccessResponse;

    private URI redirectTo;

    public Redirect(RedirectToSupplier redirectToSupplier, boolean isSuccessResponse) {
        this.redirectToSupplier = redirectToSupplier;
        this.isSuccessResponse = isSuccessResponse;
    }

    /**
     * Supply URI for redirect.
     *
     * <p>If isSuccessResponse is true, createRedirectTo create URI along with data store access for
     * generate and persistent tokens.
     *
     * @return redirectTo
     */
    public URI createRedirectTo() {
        if (this.redirectTo != null) {
            return this.redirectTo;
        }
        this.redirectTo = this.redirectToSupplier.get().redirectTo;
        return this.redirectTo;
    }

    /** If the response is success response, return true. */
    public boolean isSuccessResponse() {
        return isSuccessResponse;
    }
}
