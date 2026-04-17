package com.Aadi.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.Aadi.entity.User;
import com.Aadi.exception.UsernotfoundException;
import com.Aadi.repo.UserRepository;
@Service
public class CustomUserdeatils implements UserDetailsService {
@Autowired
	UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		 Optional<User> users=   userRepository.findByUsername(username);
		  
		 if(users.isPresent()) {
		User user =	 users.get();
		return org.springframework.security.core.userdetails.User.withUsername(username).password(user.getPassword()).roles(user.getRole()).build();
		 }else {
			 throw new UsernotfoundException("User is not found at this username : "+username);
		 }
		 
		 
		 
		  
	}

	
	
	
}
