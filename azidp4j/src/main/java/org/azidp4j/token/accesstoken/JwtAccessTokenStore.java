// package org.azidp4j.token.accesstoken;
//
// public class JwtAccessTokenStore implements AccessTokenStore{
//
//    @Override
//    synchronized public void save(InMemoryAccessToken token) {
//        STORE.put(token.token, token);
//        STORE_BY_AUTHORIZATION_CODE.put(token.authorizationCode, token);
//    }
//
//    @Override
//    public InMemoryAccessToken find(String token) {
//        return STORE.get(token);
//    }
//
//    @Override
//    synchronized public InMemoryAccessToken remove(String token) {
//        var at = STORE.remove(token);
//        return STORE_BY_AUTHORIZATION_CODE.remove(at.authorizationCode);
//    }
//
//    @Override
//    synchronized public InMemoryAccessToken removeByAuthorizationCode(String code) {
//        var at = STORE_BY_AUTHORIZATION_CODE.remove(code);
//        return STORE.remove(at.token);
//    }
// }
