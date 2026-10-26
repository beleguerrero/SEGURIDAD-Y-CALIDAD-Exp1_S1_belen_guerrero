package cl.duoc.level_start;

// import org.springframework.boot.security.autoconfigure.SecurityProperties.User;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Description;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import cl.duoc.level_start.jwt.JwtFilter;

@Configuration 
@EnableWebSecurity 
public class WebSecurityConfig {

    @Bean 
    @Order(1)
    public SecurityFilterChain apFilterChain(HttpSecurity http, JwtFilter jwtFilter) throws Exception {
        http
        .securityMatcher("/api/**")
        .csrf(csrf -> csrf.disable())
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth.requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll().anyRequest().authenticated())
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    @Bean 
    @Order(2)
    public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
        http
        .authorizeHttpRequests(
            requests -> requests
            .requestMatchers("/", "/home", "/403").permitAll()
            .requestMatchers("/registro").permitAll()
            .requestMatchers("/tailwind.config.js").permitAll()
            .requestMatchers("/**.css").permitAll()
            .anyRequest().authenticated()
        )
        .formLogin(
            form -> form
            .loginPage("/login")
            .defaultSuccessUrl("/home", true)
            .permitAll()
        )
        .exceptionHandling(
            exception -> exception
            .authenticationEntryPoint((request, response, authException) ->
                response.sendRedirect("/403")
            )
            .accessDeniedPage("/403")
        )
        .logout(logout -> logout.permitAll());

        return http.build();
    }


    @Bean 
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    
    @Bean 
    @Description("3 usuarios en memoria")
    public UserDetailsManager users() {
        UserDetails yo = User.builder().username("belen_g").password(passwordEncoder().encode("pass1")).roles("USER").build();
        UserDetails edward = User.builder().username("edward_c").password(passwordEncoder().encode("pass1")).roles("USER").build();
        UserDetails bella = User.builder().username("bella_s").password(passwordEncoder().encode("pass1")).roles("USER").build();

        return new InMemoryUserDetailsManager(yo, edward, bella);
    }

}
