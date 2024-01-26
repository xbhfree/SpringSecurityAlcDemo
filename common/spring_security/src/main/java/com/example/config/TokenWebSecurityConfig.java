package java.com.example.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
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

import java.com.example.filter.TokenAuthFilter;
import java.com.example.filter.TokenLoginFilter;
import java.com.example.security.DefaultPasswordEncoder;
import java.com.example.security.TokenLogoutHandler;
import java.com.example.security.TokenManager;
import java.com.example.security.UnauthEntryPoint;
import java.io.IOException;

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
    public AuthenticationManager authenticationManager(AuthenticationConfiguration  authenticationConfiguration) throws Exception{
        return authenticationConfiguration.getAuthenticationManager();

        /*DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userService);
        ProviderManager pm = new ProviderManager(daoAuthenticationProvider);
        return pm;*/
    }
    @Bean
    protected TokenLoginFilter tokenLoginFilter(){
        return new TokenLoginFilter(authenticationManager(),tokenManager, redisTemplate);
    }

    @Bean
    protected TokenAuthFilter tokenAuthFilter(){
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
