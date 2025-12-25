package com.example.demo.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class BcryptUtil {
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);


    public String encodePassword(String plaintextPassword) {
        return encoder.encode(plaintextPassword);
    }



}
