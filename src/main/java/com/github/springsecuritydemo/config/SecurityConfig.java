package com.github.springsecuritydemo.config;

import com.github.springsecuritydemo.entity.User;
import com.github.springsecuritydemo.service.UserService;
import com.github.springsecuritydemo.util.MyUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 忽略静态资源的访问
        // resources 所有的资源全部不需要 security 拦截
        web.ignoring().antMatchers("/resources/**");
    }

    /**
     * AuthenticationManger 认证的核心接口
     * ProviderManager: AuthenticationManager 默认的实现类
     * AuthenticationProvider：ProviderManager 持有一组 AuthenticationProvider;每个 AuthenticationProvider 负责一种认证
     * 委托模式：ProviderManger 将认证委托给 AuthenticationProvider
     * <p>
     * Authentication 用于封装认证信息的接口，不同的实现类代表不同类型的认证信息
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 认证 authentication
        // auth.userDetailsService(userService).passwordEncoder(new Pbkdf2PasswordEncoder("1234"));

        // 自定义认证规则
        auth.authenticationProvider(new AuthenticationProvider() {
            //
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                String username = authentication.getName();
                String password = (String) authentication.getCredentials();

                User user = userService.findUserByName(username);
                if (user == null) {
                    throw new UsernameNotFoundException("账号不存在");
                }
                password = MyUtil.md5(password + user.getSalt());
                if (!user.getPassword().equals(password)) {
                    throw new BadCredentialsException("密码错误");
                }
                // principal 认证的主要信息 通常是 user
                // credentials 证书，通常是密码 password
                // authorities 权限
                return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
            }

            // 返回当前的接口支持的认证类型
            // 当前的 AuthenticationProvider 支持哪种类型的认证
            @Override
            public boolean supports(Class<?> authentication) {
                return UsernamePasswordAuthenticationToken.class.equals(authentication);
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 登陆相关的配置
        http.formLogin()
                .loginPage("/loginpage")
                .loginProcessingUrl("/login") //登陆处理的路径
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        // 成功跳转到首页
                        httpServletResponse.sendRedirect("/index");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        // 失败回到登陆页面，并且给到一个错误提示
                        httpServletRequest.setAttribute("error", e.getMessage());
                        httpServletRequest.getRequestDispatcher("/loginpage").forward(httpServletRequest, httpServletResponse);
                    }
                });

        // 退出相关的配置
        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/index");
                    }
                });

        // 授权相关的配置
        http.authorizeRequests()
                .antMatchers("/letter").hasAnyAuthority("USER", "ADMIN")
                .antMatchers("/admin").hasAnyAuthority("ADMIN")
                .and().exceptionHandling().accessDeniedPage("/denied");

        // 验证码
        // 增加 自定义的 Filter 处理 验证码
        // 验证码的逻辑应该是在账号密码之前，所以在 UsernamePasswordAuthenticationFilter 之前
        http.addFilterBefore(new Filter() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                HttpServletRequest request = (HttpServletRequest) servletRequest;
                HttpServletResponse response = (HttpServletResponse) servletResponse;
                if (request.getServletPath().equals("/login")) {
                    String verifyCode = request.getParameter("verifyCode");
                    if (verifyCode == null || !verifyCode.equalsIgnoreCase("1234")) {
                        request.setAttribute("error", "验证码错误");
                        request.getRequestDispatcher("/loginpage").forward(request, response);
                        return;
                    }
                }
                // 让请求继续向下走 走到下一个 filter
                filterChain.doFilter(request, response);
            }
        }, UsernamePasswordAuthenticationFilter.class);


        // 记住我 rememberMe
        http.rememberMe()
                // 记到 内存中；如果想要存储到redis或数据库中 自己实现
                .tokenRepository(new InMemoryTokenRepositoryImpl())
                .tokenValiditySeconds(3600 * 24)
                .userDetailsService(userService);
    }
}
