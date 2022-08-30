package com.imooc.uaa.util;

import com.imooc.uaa.config.AppProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Component
public class JwtUtil {
    //用于签名访问令牌
    public static final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    public static final Key refreshKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    private final AppProperties appProperties;

   public boolean validateAccessToken(String token){
        return validateToken(token,key);
   }

   public boolean  validateRefreshToken(String token){
        return validateToken(token,refreshKey);
   }

   public boolean validateWithoutExpiration(String jwtToken){
        try{
            Jwts.parserBuilder().setSigningKey(JwtUtil.key).build().parseClaimsJws(jwtToken);
            return true;
        }catch(ExpiredJwtException | SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e){
           //如果异常是过期异常则属于正常
             if(e instanceof ExpiredJwtException){
                 return true;
             }
        }
            return false;
   }

   private boolean validateToken(String jwtToken,Key signKey){
        try{
            Jwts.parserBuilder().setSigningKey(signKey).build().parseClaimsJws(jwtToken);
            return true;
        }catch(ExpiredJwtException | SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e){
            return false;
        }
   }


   public String buildAccessTokenWithRefreshToken(String jwtToken){
        return parseClaims(jwtToken,refreshKey)
            .map(claims -> Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis()+appProperties.getJwt().getAccessTokeExpireTime()))
                .signWith(key,SignatureAlgorithm.HS512).compact()
            ).orElseThrow();
   }

   public Optional<Claims>  parseClaims(String jwtToken,Key key){
       try{
          val claims =  Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwtToken).getBody();
           return Optional.of(claims);
       }catch(Exception e){
         return Optional.empty();
       }
   }


    public String createAccessToken(UserDetails userDetails){
       return createJwtToken(userDetails,appProperties.getJwt().getAccessTokeExpireTime(),key);
    }

    public String createRefreshToken(UserDetails userDetails){
        return createJwtToken(userDetails,appProperties.getJwt().getRefreshTokeExpireTime(),refreshKey);
    }

    public String createJwtToken(UserDetails userDetails,long timeToExpire,Key key){
        val now = System.currentTimeMillis();
        return Jwts.builder()
            .setId("mooc")
            .claim("authorities",userDetails.getAuthorities().stream()
                    //.map(authority->authority.getAuthority())
                .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()))//变换处理 然后在收集成一个流
            //Sets the JWT Claims sub (subject) value. A null value will remove the property from the Claims. This is a convenience method. It will first ensure a Claims instance exists as the JWT body and then set the Claims subject field w
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date(now)) //签发时间
            .setExpiration(new Date(now+timeToExpire)) //过期时间
            .signWith(key,SignatureAlgorithm.HS512)
            .compact();//压缩

    }
}
