package com.example;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Iterator;

/**
 * ClassName: CustomAccessDecisionManager
 * 此类是决策器： 用来对 用户应有的角色,与URL地址可以访问的角色进行对比,如果不匹配则抛出异常
 *
 *
 * AbstractSecurityInterceptor 中  会 回调  FilterInvocationSecurityMetadataSource1 拿到 url 对应所需 角色信息。
 * 然后 拿到 当前 Authentication 的 认证用户信息。 然后 回调 当前  CustomAccessDecisionManager 来匹配 url 需要 role 是否 满足
 * FilterInvocationSecurityMetadataSource1 返回的 roles 集合信息
 *
 * 这个可以不自己定义。 通过实现 Voter 来定义即可
 *
 * @author L.G
 * @Description 自定义 AccessDecisionManager
 * @email lg10000@126.com
 * @date 2018年8月27日 下午4:34:07
 */
@Component
public class CustomAccessDecisionManager implements AccessDecisionManager {

    /**
     * 当 Authentication 的 username = anonymousUser 代表没有登录
     * @param authentication  当前认证的用户
     * @param object
     * @param configAttributes   访问改 uri 所需权限列表
     * @throws AccessDeniedException
     * @throws InsufficientAuthenticationException
     *
     *  如果匹配 则retrun  否则抛出异常
     */
    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
            throws AccessDeniedException, InsufficientAuthenticationException {
        // 访问的该url 不需要权限。
        if (null == configAttributes || configAttributes.size() < 1) {
            throw new AccessDeniedException("权限不足");
        }
        // 拿到 filterInvocation 返回的 url  role 对应表
        for(Iterator<ConfigAttribute> iterator =configAttributes.iterator() ;iterator.hasNext();) {
            ConfigAttribute configAttribute =  iterator.next();

            // 拿到用户 对应的 所有权限信息 和 访问url 所需要的 权限信息对比 如果 有这个 权限 则返回 否则直接抛出异常
            for(Iterator<? extends GrantedAuthority> author = authentication.getAuthorities().iterator();author.hasNext();){
                GrantedAuthority grantedAuthority =  author.next();
                if (configAttribute.getAttribute().equals(grantedAuthority.getAuthority())) {
                    return;
                }
            }
        }



        throw new AccessDeniedException("权限不足");
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

}
