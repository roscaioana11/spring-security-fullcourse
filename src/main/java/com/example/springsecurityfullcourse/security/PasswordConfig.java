package com.example.springsecurityfullcourse.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {

    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(20); //BCryptPasswordEncoder ->most popular password encoder
    }
}
