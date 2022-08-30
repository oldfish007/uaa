package com.imooc.uaa.util;

import com.imooc.uaa.config.AppProperties;
import com.imooc.uaa.domain.Role;
import com.imooc.uaa.domain.User;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.List;
import java.util.Set;


import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
public class JwtUtilUnitTests {
    private JwtUtil jwtUtil;
    @BeforeEach
    public void setup(){
        jwtUtil = new JwtUtil(new AppProperties());
    }

    @Test
    public void giveUserDetail_thenCreateTokenSuccess(){
        val username="user";
        val authorities  = Set.of(Role.builder()
            .authority("ROLE_USER")
            .build(),
            Role.builder()
                .authority("ROLE_ADMIN")
                .build());
        val user = User.builder()
            .username(username)
            .authorities(authorities)
            .build();
        //首先生成token
        val token = jwtUtil.createAccessToken(user);
        //解析
        val parsedClaims = Jwts.parserBuilder()
            //Sets the signing key used to verify any discovered JWS digital signature
            .setSigningKey(JwtUtil.key)
            .build()
            .parseClaimsJws(token)
            .getBody();
        //解析后和一开始进行一个比较
        assertEquals(username,parsedClaims.getSubject(),"解析后Subject和用户名一致");
    }
}
