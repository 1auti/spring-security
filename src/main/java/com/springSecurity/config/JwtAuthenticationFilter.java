package com.springSecurity.config;

import com.springSecurity.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
   
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService; 
    private final TokenRepository repository; 
    
    
    @Override
    protected void doFilterInternal(
/*Cuando usas @NonNull, Lombok genera automáticamente verificaciones de nulidad en el código, lo que puede ayudar a prevenir errores de tiempo de ejecución 
causados por valores null en lugares donde no se espera. Esto puede ser particularmente útil para mejorar la robustez y la claridad del código.*/
           @NonNull HttpServletRequest request, 
           @NonNull HttpServletResponse response, 
           @NonNull FilterChain filterChain
                                    ) throws ServletException, IOException {
      
        
        final String authHeader = request.getHeader("AUTHORIZATION"); 
        final String jwt;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
             filterChain.doFilter(request, response);
             return;
        }
         
         jwt = authHeader.substring(7);
         userEmail = jwtService.extractUsername(jwt);
         
          if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
      if (jwtService.isTokenValid(jwt, userDetails)) {  
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
            userDetails,
            null,
            userDetails.getAuthorities()
        );
        authToken.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(request)
        );
        SecurityContextHolder.getContext().setAuthentication(authToken);
      }
    }
    filterChain.doFilter(request, response);
         
    }
    
}

