package org.azidp4j.authorize.response;

public enum NextAction {
    /** Service should redirect. */
    redirect,

    /** Service should send errorPage. */
    errorPage,

    /** Service ask user additional action like login. */
    additionalPage,
}
