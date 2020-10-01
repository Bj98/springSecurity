package com.example.springSecurity.security;

import com.example.springSecurity.auth.ApplicationUserService;
import com.example.springSecurity.jwt.JwtConfig;
import com.example.springSecurity.jwt.JwtTokenVerifier;
import com.example.springSecurity.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.example.springSecurity.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, SecretKey secretKey, JwtConfig jwtConfig) {
        this.passwordEncoder =passwordEncoder ;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    /*
     *BASIC AUTHENTICATION using spring generated security password.

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/","/index","/css/*","/js/*")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }
    */


    /*
     *
     * ROLES AND PERMISSION BASED AUTHENTICATION
     * CSRF Disabling


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/","/index","/css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(EMPLOYEE.name())
                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(WORK_WRITE.getPermission())
                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(WORK_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(WORK_WRITE.getPermission())
                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

     */


    /*
    Permission based authentication on method level.
    Using preAuthorize()
    CSRF->Cross Site Request Forgery(Using X-XSRF-TOKEN)


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                 .csrf()
                .csrfTokenRepository(new CookieCsrfTokenRepository().withHttpOnlyFalse())
                .and()
                .authorizeRequests()
                .antMatchers("/","/index","/css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(EMPLOYEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }
    */

    /*
    Form based authentication
    Custom Login Page Using login.html & TemplateController
    Extend session using rememberMe()

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/","/index","/css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(EMPLOYEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/works",true)
                .and()
                .rememberMe() //default to 2 weeks
                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
                    .key("somethingverysecured");

    }

    */
    /*
    Customize logout using logOut()
    Parameters set for password, username and remember-me


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/","/index","/css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(EMPLOYEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .defaultSuccessUrl("/works",true)
                    .passwordParameter("password")
                    .usernameParameter("username")
                .and()
                .rememberMe() //default to 2 weeks
                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
                    .key("somethingverysecured")
                    .rememberMeParameter("remember-me")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID","remember-me")
                    .logoutSuccessUrl("/login");

    }

     */


    /*
     * User based authentication
     * Uses password encoder
     * User roles(WORKER & ADMIN) and permissions(READ & WRITE)
     * Authorities based authentication using .authorities()

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails bijayUser= User.builder()
                .username("bijay")
                .password(passwordEncoder.encode("password"))
//                .roles(EMPLOYEE.name()) //ROLE->EMPLOYEE
                .authorities(EMPLOYEE.getGrantedAuthorities())
                .build();

        UserDetails bibekUser=User.builder()
                .username("bibek")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMIN.name()) //ROLE->ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails sagarUser=User.builder()
                .username("sagar")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMINTRAINEE.name()) //ROLE->ADMINTRAINEE
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                bijayUser,
                bibekUser,
                sagarUser
        );
    }
     */

    /*
    JWT
    Make session stateless using sessionManagement()
    Add filter using addFilter()

     */


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(secretKey,jwtConfig),JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "/index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(EMPLOYEE.name())
                .anyRequest()
                .authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
