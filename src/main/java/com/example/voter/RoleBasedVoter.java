package com.example.voter;


import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;

//@Component
public class RoleBasedVoter implements AccessDecisionVoter<Object> {

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        // 识别 该url 不需要权限
        List<ConfigAttribute> ca= (List<ConfigAttribute>) attributes;
        if (ca.size() > 0 && ca.get(0) == null) {
            return ACCESS_GRANTED;
        }

        Collection<? extends GrantedAuthority> authorities = extractAuthorities(authentication);
        // 判断此url 所需要的 role 该用户是否持有 不持有 直接抛出异常

        // 这里害需要处理一个东西 就是。这个url本身 是不需要 对应的权限 只要登录就可以访问的。
        // 那么返回的 list 里面 index=0 = null  这儿应该 判断 如果 get(0) == null  成立 直接放行
        for (ConfigAttribute attribute : attributes) {
            if(attribute ==null || attribute.getAttribute() == null){
                continue;
            }
            for (GrantedAuthority authority : authorities) {
                if (attribute.getAttribute().equals(authority.getAuthority())) {
                    return ACCESS_GRANTED;
                }
            }

        }

        throw  new AccessDeniedException("没有对应的权限访问此url");
    }

    Collection<? extends GrantedAuthority> extractAuthorities(
            Authentication authentication) {
        return authentication.getAuthorities();
    }

    @Override
    public boolean supports(Class clazz) {
        return true;
    }
}