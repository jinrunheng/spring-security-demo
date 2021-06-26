package com.github.springsecuritydemo.util;

import org.apache.commons.lang3.StringUtils;
import org.springframework.util.DigestUtils;

public class MyUtil {

    public static String md5(String key) {
        if (StringUtils.isBlank(key)) {
            return null;
        }
        return DigestUtils.md5DigestAsHex(key.getBytes());
    }

}