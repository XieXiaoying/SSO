package com.sso.auth.controller;

import com.sso.auth.utils.JwtUtil;
//import com.sso.auth.entity.User;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class LoginController {
    private static final String jwtTokenCookieName = "JWT-TOKEN";
    private static final String signingKey = "signingKey";

    @GetMapping(value = "/setToken")
    public ResponseEntity setToken(String username){
        String token = JwtUtil.generateToken(signingKey, username);
        return new ResponseEntity(token, HttpStatus.OK);
    }
    @GetMapping(value = "/removeToken")
    public ResponseEntity removeToken(HttpServletRequest httpServletRequest){
        JwtUtil.invalidateRelatedTokens(httpServletRequest, jwtTokenCookieName);
        return new ResponseEntity("ok", HttpStatus.OK);
    }
    @GetMapping(value = "/containsToken")
    public ResponseEntity containsToken(HttpServletRequest httpServletRequest){
        String subject = JwtUtil.parseToken(httpServletRequest, jwtTokenCookieName, signingKey);
        if(subject.equals("expired token") || subject.equals("invalid token")){
            return new ResponseEntity(subject, HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity(subject, HttpStatus.OK);
    }
}
