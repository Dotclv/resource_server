package com.example;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.*;


@Component
public class FilterInvocationSecurityMetadataSource1 implements FilterInvocationSecurityMetadataSource {

    // 这里的需要从DB加载  value 可以是 roles  /xxx/xx  ADMIN,ROLE1,ROLE2
    private final Map<String,String> urlRoleMap = new HashMap<String,String>(){
        {
            put("/open/**","admin");
            put("/test/**","role1,role2");
            put("/restart","role2");
            put("/test/te/1","role2");
        }
    };


    public FilterInvocationSecurityMetadataSource1(){

    }


    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        FilterInvocation fi = (FilterInvocation) object;
        String url = fi.getRequest().getRequestURI();

        for(Map.Entry<String,String> entry:urlRoleMap.entrySet()){
            if(antPathMatcher.match(entry.getKey(),url)){
                // 拿到 uri 所需权限集合 返回 在 CustomAccessDecisionManager 进行验证
                return SecurityConfig.createList(entry.getValue().split(","));
            }
        }

        List<ConfigAttribute> objects = new ArrayList<>();
        objects.add(null);// 如果 不加null isEmput 为 true  直接无法下发 过去了。 在security 默认自己的 filter 会返回一个默认的
        //configAttribute 来解析 当前 url 是否不需要角色
        //  返回空对应url 没有所需权限 列表
        return null;
    }
    private static final AntPathMatcher antPathMatcher = new AntPathMatcher();


    public static void main(String[] args) {
        System.out.println(antPathMatcher.match("/a/**", "/a"));
    }

    private String getCurUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User principal = (User) authentication.getPrincipal();
        String username = principal.getUsername();

        return username;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
