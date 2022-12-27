package org.azidp4j.authorize;

import org.azidp4j.authorize.request.CodeChallengeMethod;

public class CodeChallenge {
    private final CodeChallengeMethod codeChallengeMethod;
    private final String codeChallenge;

    public CodeChallenge(CodeChallengeMethod codeChallengeMethod, String codeChallenge) {
        this.codeChallengeMethod = codeChallengeMethod;
        this.codeChallenge = codeChallenge;
    }

    public CodeChallengeMethod getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }
}
