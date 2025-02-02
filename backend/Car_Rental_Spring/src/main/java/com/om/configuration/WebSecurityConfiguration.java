package com.om.configuration;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import com.om.enums.UserRole;
import com.om.services.jwt.UserService;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfiguration {
	
	private final JWTAuthenticationFilter jwtAuthenticationFilter;
	
	private final UserService userService;

	public WebSecurityConfiguration(JWTAuthenticationFilter jwtAuthenticationFilter, UserService userService) {
		super();
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
		this.userService = userService;
	}
	
	
//	@Bean
//	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//	    http
//	        .csrf(AbstractHttpConfigurer::disable)
//	        .authorizeHttpRequests(request -> request
//	            .requestMatchers("/api/auth/**").permitAll()
//	            .requestMatchers("/api/admin/**").hasAuthority(UserRole.ADMIN.name()) 
//	            .requestMatchers("/api/customer/**").hasAuthority(UserRole.CUSTOMER.name()) 
//	            .anyRequest().authenticated()
//	        )
//	        .sessionManagement(manager -> 
//	            manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//	        )
//	        .authenticationProvider(authenticationProvider())
//	        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
//	    	    
//	    return http.build();
//	}
	
	
//	//gpt
//	@Bean
//	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//	    http
//	        .cors(cors -> cors.configurationSource(request -> {
//	            CorsConfiguration config = new CorsConfiguration();
//	            config.setAllowedOrigins(Arrays.asList("*"));
//	            config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//	            config.setAllowedHeaders(Arrays.asList("*"));
//	            return config;
//	        }))
//	        .csrf(AbstractHttpConfigurer::disable)
//	        .authorizeHttpRequests(request -> request
//	            .requestMatchers("/api/auth/**").permitAll()
//	            .requestMatchers("/api/admin/**").hasAuthority(UserRole.ADMIN.name()) 
//	            .requestMatchers("/api/customer/**").hasAuthority(UserRole.CUSTOMER.name()) 
//	            .anyRequest().authenticated()
//	        )
//	        .sessionManagement(manager -> 
//	            manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//	        )
//	        .authenticationProvider(authenticationProvider())
//	        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
//	        
//	    return http.build();
//	}
	
	
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(Customizer.withDefaults())  // Enable CORS
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(request -> request
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // Allow OPTIONS requests
                .requestMatchers("/api/auth/login").permitAll()  // Explicitly permit login endpoint
                .requestMatchers("/api/auth/signup").permitAll() // Explicitly permit signup endpoint
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/admin/**").hasAuthority(UserRole.ADMIN.name()) 
                .requestMatchers("/api/customer/**").hasAuthority(UserRole.CUSTOMER.name()) 
                .anyRequest().authenticated()
            )
            .sessionManagement(manager -> 
                manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authenticationProvider(authenticationProvider())
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
            
        return http.build();
    }
	
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthenticationProvider authenticationProvider() {
	    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
	    authProvider.setUserDetailsService(userService.userDetailsService());
	    authProvider.setPasswordEncoder(passwordEncoder());   
	    return authProvider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
	    return config.getAuthenticationManager();
	}



}
