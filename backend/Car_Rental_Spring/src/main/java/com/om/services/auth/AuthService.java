package com.om.services.auth;

import com.om.dto.SignUpRequest;
import com.om.dto.UserDto;

public interface AuthService {
	
	UserDto createCustomer(SignUpRequest signUpRequest);
	
	boolean hasCustomerWithEmail(String email);

}
