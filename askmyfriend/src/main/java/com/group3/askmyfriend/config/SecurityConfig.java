// src/main/java/com/group3/askmyfriend/config/SecurityConfig.java
package com.group3.askmyfriend.config;

import com.group3.askmyfriend.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

@Configuration
@RequiredArgsConstructor
@Order(2)
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final AuthenticationFailureHandler customAuthFailureHandler;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider userAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 웹/세션 전용 체인
            .securityMatcher("/**")
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(sm ->
                sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            )
            .authenticationProvider(userAuthenticationProvider())
            .authorizeHttpRequests(auth -> auth
                // 공개
                .requestMatchers(
                    "/",
                    "/auth/login", "/auth/loginProc", "/auth/signup",
                    "/auth/find-password", "/auth/send-code", "/auth/verify-code", "/auth/reset-password",
                    "/css/**", "/js/**", "/images/**", "/error/**"
                ).permitAll()

                // 세션 기반으로 보호할 API (팔로우)
                .requestMatchers(HttpMethod.GET,    "/api/follow/**").authenticated()
                .requestMatchers(HttpMethod.POST,   "/api/follow/**").authenticated()
                .requestMatchers(HttpMethod.DELETE, "/api/follow/**").authenticated()

                // 웹 뷰 보호
                .requestMatchers("/friends/**", "/friend-management/**").authenticated()
                .requestMatchers("/setting/change-passwordProc").authenticated()

                // 관리자
                .requestMatchers("/admin/**").hasRole("ADMIN")

                // 그 외
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/auth/login")
                .loginProcessingUrl("/auth/loginProc")
                .usernameParameter("loginId")
                .passwordParameter("password")
                .defaultSuccessUrl("/index", true)
                .failureHandler(customAuthFailureHandler)
            )
            .httpBasic(AbstractHttpConfigurer::disable)
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/auth/login")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
            );

        return http.build();
    }
}
