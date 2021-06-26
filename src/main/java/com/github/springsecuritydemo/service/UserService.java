package com.github.springsecuritydemo.service;

import com.github.springsecuritydemo.dao.UserMapper;
import com.github.springsecuritydemo.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserMapper userMapper;

    public User findUserByName(String username) {
        return userMapper.selectByName(username);
    }
}
