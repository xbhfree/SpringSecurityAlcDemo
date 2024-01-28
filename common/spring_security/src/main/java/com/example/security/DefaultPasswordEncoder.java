package com.example.security;

import com.example.utils.MD5;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 密码处理
 */
public class DefaultPasswordEncoder implements PasswordEncoder {
    public DefaultPasswordEncoder(){

    }

    public DefaultPasswordEncoder(int strLength){

    }
    //进行md5加密
    public String encode(CharSequence rawPassword) {
        return MD5.encrypt(rawPassword.toString());
    }

    //进行密码比对
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return encodedPassword.equals(rawPassword.toString());
    }
}
