package com.imooc.uaa.security.filter;

import com.imooc.uaa.config.AppProperties;
import com.imooc.uaa.util.CollectionUtil;
import com.imooc.uaa.util.JwtUtil;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtFilter extends OncePerRequestFilter {

    private final AppProperties appProperties;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //检查 JWT Token 是否在 HTTP 报头中
        if(checkJwtToken(request)){
            validateToken(request)
                .filter(claims -> claims.get("authorities")!=null)
                .ifPresentOrElse(
                    //有值
                    claims -> {
                        //把对象转换成集合
                        setupSpringAuthentication(claims);
                    },
                    //空值
                    ()->{

                        SecurityContextHolder.clearContext();
                    }
                );
            //如果有 解析token 拆出来 实例化UsernamePasswordAuthenticationToken
            //放到SecurityContext
        }
            filterChain.doFilter(request,response);
    }

    private void setupSpringAuthentication(Claims claims) {
        val rawList = CollectionUtil.convertObjectToList(claims.get("authorities"));
        val  authorities =  rawList.stream()
            //转换成字符串
            .map(str->String.valueOf(str))
            .map(strAuthority->new SimpleGrantedAuthority(strAuthority))
            .collect(Collectors.toList());
        val authentication = new UsernamePasswordAuthenticationToken(claims.getSubject(),null,authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    /**
     * 取到token
     * @param request
     * @return
     */
    private Optional<Claims> validateToken(HttpServletRequest request){
        String jwtToken = request.getHeader(appProperties.getJwt().getHeader()).replace(appProperties.getJwt().getPrefix(), "");
         try{
           return  Optional.of(Jwts.parserBuilder().setSigningKey(JwtUtil.key).build().parseClaimsJws(jwtToken).getBody());
         }catch(ExpiredJwtException | SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e){
            return  Optional.empty();
         }
    }

    /**
     * 检查 JWT Token 是否在 HTTP 报头中
     *
     * @param req HTTP 请求
     * @return 是否有 JWT Token
     */
    private boolean checkJwtToken(HttpServletRequest request) {
        String authenticationHeader = request.getHeader(appProperties.getJwt().getHeader());
        return authenticationHeader!= null && authenticationHeader.startsWith(appProperties.getJwt().getPrefix());
    }
}
