package com.om.controller;

import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.om.dto.AuthenticationRequest;
import com.om.dto.AuthenticationResponse;
import com.om.dto.SignUpRequest;
import com.om.dto.UserDto;
import com.om.entity.User;
import com.om.repository.UserRepository;
import com.om.services.auth.AuthService;
import com.om.services.jwt.UserService;
import com.om.utils.JWTUtil;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final AuthService authService;
	
	private final AuthenticationManager authenticationManager;
	
	private final UserService userService;
	
	private final JWTUtil jwtUtil;
	
	private final UserRepository userRepository;


	public AuthController(AuthService authService, AuthenticationManager authenticationManager, UserService userService,
			JWTUtil jwtUtil, UserRepository userRepository) {
		this.authService = authService;
		this.authenticationManager = authenticationManager;
		this.userService = userService;
		this.jwtUtil = jwtUtil;
		this.userRepository = userRepository;
	}




	@PostMapping("/signup")
	public ResponseEntity<?> signUpCustomer(@RequestBody SignUpRequest signUpRequest){
		
		if (authService.hasCustomerWithEmail(signUpRequest.getEmail())) {
			return new ResponseEntity<>("Customet with this email alreadt exists", HttpStatus.NOT_ACCEPTABLE);
		}
		
		UserDto createdCustomerDto = authService.createCustomer(signUpRequest);
		if (createdCustomerDto == null) return new ResponseEntity<>("Customer Not Created", HttpStatus.BAD_REQUEST);
		return new ResponseEntity<>(createdCustomerDto, HttpStatus.CREATED);
	}
	
	
//	@PostMapping("/login")
//	public AuthenticationResponse createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws 
//	        BadCredentialsException, 
//	        DisabledException, 
//	        UsernameNotFoundException {
//	    try {
//	    	
//	    	System.out.println("============GET EMAIL========="+authenticationRequest.getEmail());
//	    	System.out.println("============GET PASSWORD========="+authenticationRequest.getPassword());
//	    	
//	        authenticationManager.authenticate(
//	            new UsernamePasswordAuthenticationToken(
//	                authenticationRequest.getEmail(), 
//	                authenticationRequest.getPassword()
//	            )
//	        );
//	    } catch (BadCredentialsException e) {
//	        throw new BadCredentialsException("Incorrect username or password.");
//	    }
//
//	    final UserDetails userDetails = userService.userDetailsService().loadUserByUsername(authenticationRequest.getEmail());
//	    Optional<User> optionalUser = userRepository.findFirstByEmail(userDetails.getUsername());
//	    
//	    final String jwt = jwtUtil.generateToken(userDetails);
//	    AuthenticationResponse authenticationResponse = new AuthenticationResponse();
//
//	    if (optionalUser.isPresent()) {
//	        authenticationResponse.setJwt(jwt);
//	        authenticationResponse.setUserId(optionalUser.get().getId());
//	        authenticationResponse.setUserRole(optionalUser.get().getUserRole());
//	        return authenticationResponse;
//	    }
//
//	    // Handle the case when user is not found in the database
//	    throw new UsernameNotFoundException("User not found");
//	}
	
	
	@PostMapping("/login")
	public AuthenticationResponse createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws 
	        BadCredentialsException, 
	        DisabledException, 
	        UsernameNotFoundException {
	    try {
	        System.out.println("============Starting Authentication Process=========");
	        System.out.println("Email: " + authenticationRequest.getEmail());
	        // Don't log actual passwords in production!
	        
	        Optional<User> userExists = userRepository.findFirstByEmail(authenticationRequest.getEmail());
	        System.out.println("User exists in DB: " + userExists.isPresent());
	        
	        authenticationManager.authenticate(
	            new UsernamePasswordAuthenticationToken(
	                authenticationRequest.getEmail(), 
	                authenticationRequest.getPassword()
	            )
	        );
	        System.out.println("============Authentication Successful=========");
	        
	    } catch (BadCredentialsException e) {
	        System.out.println("============Authentication Failed: Bad Credentials=========");
	        e.printStackTrace();
	        throw new BadCredentialsException("Incorrect username or password.");
	    } catch (Exception e) {
	        System.out.println("============Other Authentication Error=========");
	        e.printStackTrace();
	        throw e;
	    }

	    final UserDetails userDetails = userService.userDetailsService().loadUserByUsername(authenticationRequest.getEmail());
	    Optional<User> optionalUser = userRepository.findFirstByEmail(userDetails.getUsername());
	    
	    final String jwt = jwtUtil.generateToken(userDetails);
	    AuthenticationResponse authenticationResponse = new AuthenticationResponse();

	    if (optionalUser.isPresent()) {
	        authenticationResponse.setJwt(jwt);
	        authenticationResponse.setUserId(optionalUser.get().getId());
	        authenticationResponse.setUserRole(optionalUser.get().getUserRole());
	        return authenticationResponse;
	    }

	    // Handle the case when user is not found in the database
	    throw new UsernameNotFoundException("User not found");
	}

	
}
