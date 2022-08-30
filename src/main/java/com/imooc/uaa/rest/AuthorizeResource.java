package com.imooc.uaa.rest;

import com.imooc.uaa.domain.Auth;
import com.imooc.uaa.domain.dto.LoginDto;
import com.imooc.uaa.domain.dto.UserDto;
import com.imooc.uaa.service.UserService;
import com.imooc.uaa.util.JwtUtil;
import com.imooc.uaa.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequiredArgsConstructor
@RestController
@RequestMapping("/authorize")
public class AuthorizeResource {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    @GetMapping(value="greeting")
    public String sayHello() {
        return "hello world";
    }

    @PostMapping("/register")
    public UserDto register(@Valid @RequestBody UserDto userDto) {
        return userDto;
    }

    @GetMapping("/problem")
    public void raiseProblem() {
        throw new AccessDeniedException("You do not have the privilege");
    }

    @GetMapping("/anonymous")
    public String getAnonymous() {
        return SecurityUtil.getCurrentLogin();
    }

    @PostMapping("/token")
    public Auth login(@Valid @RequestBody LoginDto loginDto){
        return userService.login(loginDto.getUsername(),loginDto.getPassword());
    }

    /**
     * 目标使用refreshtoken 换一个新的访问accessToken
     * @param authorization
     * @param refreshToken
     * @return
     */
    @PostMapping("/token/refresh")
    public Auth refreshToken(@RequestHeader(name="Authorization") String authorization,@RequestParam String refreshToken){
        val PREFIX="Bearer ";
        val accessToken = authorization.replace(PREFIX,"");
        //校验refreshToken 且accessToken不考虑过期
        if(jwtUtil.validateRefreshToken(refreshToken) && jwtUtil.validateWithoutExpiration(accessToken)){
            //重新生成一个新的token
            return new Auth(jwtUtil.buildAccessTokenWithRefreshToken(refreshToken),refreshToken);
        }
        throw new AccessDeniedException("Bad Credentials");
    }

}
