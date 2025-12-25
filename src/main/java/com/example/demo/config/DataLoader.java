package com.example.demo.config;

import com.example.demo.model.User;
import com.example.demo.repo.UserRepo;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;

@Component
public class DataLoader implements CommandLineRunner {

    private final UserRepo userRepository;

    @Autowired
    public DataLoader(UserRepo userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void run(String... args) throws Exception {
        loadData();
    }

    public void loadData() {
        userRepository.save(new User("user", encodePassword("user")));
        userRepository.save(new User("admin", encodePassword("admin")));
        userRepository.save(new User("titan", encodePassword("titan")));
    }

    public String encodePassword(String plantextPassword) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
        return encoder.encode(plantextPassword);
    }
}

