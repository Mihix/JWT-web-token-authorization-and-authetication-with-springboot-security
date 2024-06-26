package springjwt.jwtscurity.filter;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import springjwt.jwtscurity.service.JWTService;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter   { // why extends OncePerRequestFilter , because of I want
    // this filter to be excecuted once in every incoming request

    private final JWTService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JWTService jwtService,  UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;

    }

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization"); //autheheader is must name is "Authorization"

        if(authHeader == null || !authHeader.startsWith("Bearer")){ // that condtion is true pass the next filter
            filterChain.doFilter(request,response);
            return;
        }

        String token = authHeader.substring(7);// if the index characters are 7 == token because skip the "authHeader.startsWith("Bearer")"
        String username = jwtService.extractUsername(token);



        //we can check if the user is authenticated using security
        if(username !=  null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);


         if(jwtService.isValid(token,userDetails)){ // we can check if token is valid
             UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                     userDetails,null,userDetails.getAuthorities()
             );
// why creditials is null  bacause of tokne based authentication

             authToken.setDetails( // set the details authToken
                     new WebAuthenticationDetailsSource().buildDetails(request)
             );
             SecurityContextHolder.getContext().setAuthentication(authToken);

         }
        }
        filterChain.doFilter(request,response);

    }
}
