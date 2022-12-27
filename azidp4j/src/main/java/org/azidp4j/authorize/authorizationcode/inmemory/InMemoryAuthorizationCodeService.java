package org.azidp4j.authorize.authorizationcode.inmemory;

import java.util.Optional;
import java.util.UUID;
import org.azidp4j.authorize.authorizationcode.AuthorizationCode;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.request.CodeChallengeMethod;

public class InMemoryAuthorizationCodeService implements AuthorizationCodeService {

    private final InMemoryAuthorizationCodeStore authorizationCodeStore;

    public InMemoryAuthorizationCodeService(InMemoryAuthorizationCodeStore authorizationCodeStore) {
        this.authorizationCodeStore = authorizationCodeStore;
    }

    @Override
    public AuthorizationCode issue(
            String sub,
            String scope,
            String claims,
            String clientId,
            String redirectUri,
            String state,
            Long authTime,
            String nonce,
            String codeChallenge,
            CodeChallengeMethod codeChallengeMethod,
            Long exp) {
        var ac =
                new AuthorizationCode(
                        UUID.randomUUID().toString(),
                        sub,
                        scope,
                        claims,
                        clientId,
                        redirectUri,
                        state,
                        authTime,
                        nonce,
                        codeChallenge,
                        codeChallengeMethod,
                        exp);
        authorizationCodeStore.save(ac);
        return ac;
    }

    @Override
    public Optional<AuthorizationCode> consume(String code) {
        return authorizationCodeStore.consume(code);
    }
}
