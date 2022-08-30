package com.imooc.uaa.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
//mooc.jwt.accessTokeExpireTime
@ConfigurationProperties(prefix = "mooc")
@Configuration
public class AppProperties {
    @Getter
    @Setter
    private Jwt jwt = new Jwt();

    @Getter
    @Setter
    public static class Jwt{
        private Long accessTokeExpireTime = 60_000L;
        private Long refreshTokeExpireTime = 30*24*3600*1000L;
        private String header = "Authorization";
        private String prefix = "Bearer ";
    }
}
