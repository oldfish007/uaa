package com.imooc.uaa.config;

import com.imooc.uaa.config.dsl.ClientErrorLoggingConfigurer;
import com.imooc.uaa.security.filter.JwtFilter;
import com.imooc.uaa.security.filter.RestAuthenticationFilter;
import com.imooc.uaa.security.userdetails.UserDetailsPasswordServiceImpl;
import com.imooc.uaa.security.userdetails.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.zalando.problem.spring.web.advice.security.SecurityProblemSupport;

import java.util.ArrayList;
import java.util.Map;


/**
 * 这个配置类是对api生效
 */

@RequiredArgsConstructor
@EnableWebSecurity(debug = true)
@Configuration
@Order(99)
@Import(SecurityProblemSupport.class)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final SecurityProblemSupport problemSupport;
    private final UserDetailsServiceImpl userDetailsServiceImpl;
    private final UserDetailsPasswordServiceImpl userDetailsPasswordServiceImpl;
    private final JwtFilter jwtFilter;
    //private final RestAuthenticationFilter restAuthenticationFilter;
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .requestMatchers(req -> req.mvcMatchers("/api/**", "/admin/**", "/authorize/**"))
            .sessionManagement(sessionManagement -> sessionManagement
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(exceptionHandling -> exceptionHandling
                .authenticationEntryPoint(problemSupport)
                .accessDeniedHandler(problemSupport))
            .authorizeRequests(authorizeRequests -> authorizeRequests
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/api/**").hasRole("USER")
                .anyRequest().authenticated())
            //.addFilterAt(restAuthenticationFilter,UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .csrf(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(httpBasic -> httpBasic.authenticationEntryPoint(problemSupport))//在认证头里面做一个base64
            ;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
            .ignoring()
            .antMatchers(
                "/authorize/**",
                "/error/**",
                "/h2-console/**");//添加/h2-console这个path 使他可以访问
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       /* auth
            .userDetailsService(userDetailsServiceImpl) // 配置 AuthenticationManager 使用 userService
            .passwordEncoder(passwordEncoder()) // 配置 AuthenticationManager 使用 userService
            .userDetailsPasswordManager(userDetailsPasswordServiceImpl); // 配置密码自动升级服务*/
        //后面有几个provider LDAProvider
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    /**
     * ldapProvider 没有实验成功
     * @return
     */


    @Bean
    DaoAuthenticationProvider daoAuthenticationProvider(){
        val daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsServiceImpl);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsPasswordService(userDetailsPasswordServiceImpl);
        return daoAuthenticationProvider;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public ClientErrorLoggingConfigurer clientErrorLogging() {
        return new ClientErrorLoggingConfigurer(new ArrayList<>());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // 默认编码算法的 Id
        val idForEncode = "bcrypt";
        // 要支持的多种编码器
        val encoders = Map.of(
            idForEncode, new BCryptPasswordEncoder(),
            "SHA-1", new MessageDigestPasswordEncoder("SHA-1")
        );
        return new DelegatingPasswordEncoder(idForEncode, encoders);
    }
}
