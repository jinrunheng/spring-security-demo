package com.github.springsecuritydemo.entity;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Data
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class User implements UserDetails {
    private int id;
    private String username;
    private String password;
    private String salt;
    private String email;
    private int type; // 1 代表 admin；2 代表 普通用户
    private int status;
    private String activationCode;
    private String headerUrl;
    private Date createTime;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> list = new ArrayList<>();
        list.add((GrantedAuthority) () -> {
            if (type == 1) {
                return "ADMIN";
            } else {
                return "USER";
            }
        });
        return list;
    }

    // true 账号未过期
    // false 账号过期
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // true 账号未锁定
    // false 账号锁定
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // true 凭证未过期
    // false 凭证过期
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // true 账号可以
    // false 账号不可用
    @Override
    public boolean isEnabled() {
        return true;
    }
}
