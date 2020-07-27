package com.sso.auth.utils;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;

public class JwtUtil {
    private static final String REDIS_SET_ACTIVE_SUBJECTS = "active-subjects";

    public static String generateToken(String signingKey, String subject) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        JwtBuilder builder = Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .signWith(SignatureAlgorithm.HS256, signingKey);

        String token = builder.compact();

        RedisUtil.INSTANCE.sadd(REDIS_SET_ACTIVE_SUBJECTS, subject);

        return token;
    }

    public static String parseToken(HttpServletRequest httpServletRequest, String jwtTokenCookieName, String signingKey){
        Cookie cookie = WebUtils.getCookie(httpServletRequest, jwtTokenCookieName);
        String token =  cookie != null ? cookie.getValue() : null;
        if(token == null) {
            return "invalid token";
        }
        try {
            String subject = Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token).getBody().getSubject();
            if (!RedisUtil.INSTANCE.sismember(REDIS_SET_ACTIVE_SUBJECTS, subject)) {
                return "expired token";
            }

            return subject;
        } catch (SignatureException ex){
            return "invalid token";
        }

    }

    public static void invalidateRelatedTokens(HttpServletRequest httpServletRequest, String jwtTokenCookieName) {
        RedisUtil.INSTANCE.srem(REDIS_SET_ACTIVE_SUBJECTS, (String) httpServletRequest.getParameter(jwtTokenCookieName));
    }
}

