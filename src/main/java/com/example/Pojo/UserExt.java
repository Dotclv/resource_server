package com.example.Pojo;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;


public  class UserExt extends User {
    public String gongsi;
    public String address;

    public UserExt(String username, String password, Collection<? extends GrantedAuthority> authorities, String gongsi, String address) {
        super(username, password, authorities);
        this.gongsi=gongsi;
        this.address=address;
    }
}
