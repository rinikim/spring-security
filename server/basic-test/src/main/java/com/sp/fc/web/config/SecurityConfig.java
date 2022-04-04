package com.sp.fc.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity(debug = true) // debug 모드 실행
@EnableGlobalMethodSecurity(prePostEnabled = true) // prePost 로 권한 체크를 하겠다.
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // application.yml 에서는 사용자를 1명만 추가할 수 있으므로 WebSecurityConfigurerAdapter 에서 추가해준다.

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // user Authentication provider 를 추가하게 되면 application.yml 에서 설정한 것이 실행되지 않는다.
        auth.inMemoryAuthentication()
                .withUser(User.builder()
                        .username("user2")
                        .password("2222")
                        .password(passwordEncoder().encode("2222"))
                        .roles("USER")
                ).withUser(User.builder()
                        .username("admin")
                        .password(passwordEncoder().encode("3333"))
                        .roles("ADMIN")
                );
    }

    /**
     * 사용자 패스워드 인코더
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 스프링 시큐리티는 모든 접근자를 막고 시작한다.
     * 홈페이지는 누구나 볼 수 있게 설정할 것이다.
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests((requests) ->
                requests.antMatchers("/").permitAll() // 홈페이지에선 모든 접근자 허용
                        .anyRequest().authenticated()); // authorize 에서 request 할 때 어떤 request 든 모두 인증을 받아라.
        http.formLogin();
        http.httpBasic();
    }
}
