package com.imooc.uaa.service;

import com.imooc.uaa.domain.Auth;
import com.imooc.uaa.repository.UserRepo;
import com.imooc.uaa.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    /**
     * 用户登录
     *
     * @param username 用户名
     * @param password 密码
     * @return JWT
     */
    public Auth login(String username,String password){
        return userRepo.findOptionalByUsername(username)
               //返回的是optional对象
               .filter(user->passwordEncoder.matches(password,user.getPassword()))
            //在映射一道 匹配的user 处理成auth
               .map(user -> new Auth(jwtUtil.createAccessToken(user),jwtUtil.createRefreshToken(user)))
               .orElseThrow(()->new AccessDeniedException("用户名密码错误"));
    }
}
