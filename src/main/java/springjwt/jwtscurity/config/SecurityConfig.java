package springjwt.jwtscurity.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import springjwt.jwtscurity.filter.JwtAuthenticationFilter;
import springjwt.jwtscurity.service.UserDetailsServiceImp;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final UserDetailsServiceImp userDetailsServiceImp;

    private final JwtAuthenticationFilter jwtAuthenticationFilter;



    public SecurityConfig(UserDetailsServiceImp userDetailsServiceImp, JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.userDetailsServiceImp = userDetailsServiceImp;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }


    // authorized the HHTP requesrt , using a login and register link
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

        return http
                .csrf(AbstractHttpConfigurer :: disable)
                .authorizeHttpRequests(
                        req->req.requestMatchers("/login/**","/register/**")
                                .permitAll() //get a permission
                                .requestMatchers("/admin_only/**").hasAnyAuthority("ADMIN")           //configure the authorization and I want only admin user access this url
                                .anyRequest() // any other request
                                .authenticated() //must be aithenticated
                ).userDetailsService(userDetailsServiceImp) // we neend the tell which userdetailservice spring needs to
                // use
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();

    }
// we need passowrd
    @Bean
    public PasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();

    }
}
