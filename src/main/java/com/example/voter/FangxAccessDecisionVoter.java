package com.example.voter;

import com.example.webfxUrlconfig.WebFx;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;
import java.util.List;

@Component
public class FangxAccessDecisionVoter  implements AccessDecisionVoter<Object> {

    @Autowired
    WebFx webFx;

    private AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    // 用于 处理放行的页面 如果满足条件 不必在 轮训 第二个 role - path 的 voter
    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {

        int result = ACCESS_ABSTAIN;// 0 下一个 不抛出异常

        FilterInvocation fi = (FilterInvocation) object;
        String uri = fi.getRequest().getRequestURI();
        List<ConfigAttribute> attrs=(List<ConfigAttribute>) attributes;
        // path 在自定义FilterInvocationSecurityMetadataSource1 没匹配到 需要的 roles 此处判断 是否是 放行 如果 不是放行 则 抛出异常

            // 拿到需要放行的 所有路径
        List<String> urls = webFx.getUrls();
        for (String url : urls) {
            if (antPathMatcher.match(url,uri)){
                return ACCESS_GRANTED;// 放行页面 直接 1 返回通过 不用在比对 是否有对应角色
            }
        }

        // 当过了放行的页面 必须需要认证
        if (authentication != null && authentication.getName().equalsIgnoreCase("anonymousUser")){
            throw new AccessDeniedException("未认证");
        }
        return result;// 下一个 不抛出异常
    }
}
