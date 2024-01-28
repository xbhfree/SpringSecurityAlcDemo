package com.example.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;

import com.example.filter.TokenAuthFilter;
import com.example.filter.TokenLoginFilter;
import com.example.security.DefaultPasswordEncoder;
import com.example.security.TokenLogoutHandler;
import com.example.security.TokenManager;
import com.example.security.UnauthEntryPoint;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
public class TokenWebSecurityConfig{

    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;
    private DefaultPasswordEncoder defaultPasswordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;
    //注册密码加密bean
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 注册自定义用户登录信息查询bean
     * 需要关联到自定义的子类implements UserDetailsService
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService(){
        return username -> userDetailsService.loadUserByUsername(username);
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception{
        //return authenticationConfiguration.getAuthenticationManager();

        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        ProviderManager pm = new ProviderManager(daoAuthenticationProvider);
        return pm;
    }
    @Bean
    protected TokenLoginFilter tokenLoginFilter() throws Exception{
        return new TokenLoginFilter(authenticationManager(),tokenManager, redisTemplate);
    }

    @Bean
    protected TokenAuthFilter tokenAuthFilter() throws Exception{
        return new TokenAuthFilter(authenticationManager(),tokenManager, redisTemplate);
    }
    @Bean
    SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .exceptionHandling()
                .authenticationEntryPoint(new UnauthEntryPoint())
                .and().csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable())
                .authorizeHttpRequests()
                .anyRequest().authenticated()
                .and().logout(httpSecurityLogoutConfigurer ->
                        httpSecurityLogoutConfigurer.logoutUrl("/admin/alc/index/logout"))
                .addFilter(tokenLoginFilter())
                .addFilter(tokenAuthFilter()).build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return (web) -> web.ignoring().requestMatchers("/api/**");
    }
}
