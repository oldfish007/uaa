package com.imooc.uaa.rest;

import com.imooc.uaa.util.SecurityUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api")
public class UserResource {
    @GetMapping("/me")
    public String getProfile() {
        return SecurityUtil.getCurrentLogin();
    }

    @GetMapping("/principal")
    public Principal getCurrentPrincipalName(Principal principal) {

        //return SecurityContextHolder.getContext().getAuthentication();
        return principal;
    }

    @GetMapping("/authentication")
    public Authentication getCurrentAuthentication(Authentication authentication) {
        return authentication;
    }
}
