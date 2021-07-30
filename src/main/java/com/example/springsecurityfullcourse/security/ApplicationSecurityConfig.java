package com.example.springsecurityfullcourse.security;

import com.example.springsecurityfullcourse.auth.ApplicationUserService;
import com.example.springsecurityfullcourse.jwt.JwtConfig;
import com.example.springsecurityfullcourse.jwt.JwtTokenVerifier;
import com.example.springsecurityfullcourse.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.crypto.SecretKey;
import java.util.concurrent.TimeUnit;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //sa vada @PreAuthorize din controllere
@RequiredArgsConstructor
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //trebuie pusa pt ca spring security by default is trying to protect our api
                .csrf().disable() // Cross Site Request Forgery- protejeaza website-ul de catre atacatori care vor sa puna link embedded prin care orice alt user care se logheaza ii fura bani
                //este recomandat sa fie folosit pt orice request care este procesat de catre un browser de catre uzeri normali
                //daca creezi un server care este folosit de non-browser clients, este recomandat ca csrf sa fie disabled
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) //how the token are generated and we can add some settings
//                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //linia asta de cod se adauga doar daca implementezi cu Jwt, nu pentru formLogin
                .and() //linia asta de cod se adauga doar daca implementezi cu Jwt, nu pentru formLogin
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey)) //linia asta de cod se adauga doar daca implementezi cu Jwt, nu pentru formLogin
                .addFilterBefore(new JwtTokenVerifier(secretKey, jwtConfig),JwtUsernameAndPasswordAuthenticationFilter.class) //linia asta de cod se adauga doar daca implementezi cu Jwt, nu pentru formLogin
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name()) //anything about student will access this api
                //2 ways for implementing permission based authentication
                //this is 1 way, second is by adnotations in the actual methods
//                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name()) // hasAuthority() pretty much as hasPermission
//                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name()) // hasAuthority() pretty much as hasPermission
//                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name()) // hasAuthority() pretty much as hasPermission

                //the order the antMatchers are defined, matters
                //le-am comentat pt ca folosesc prin adnotarile din controller
//                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
                .anyRequest()
                .authenticated();

        /**
         * codul de mai jos l-am comentat pentru ca am adaugat Jwt
         */
//                .and()

                //                .httpBasic(); //basic authentication
//                .formLogin() //form based authentication
//                    .loginPage("/login")
//                    .permitAll()
//                    .defaultSuccessUrl("/courses", true) //true pt force redirect
//                    .passwordParameter("password")
//                    .usernameParameter("username")
//                .and()
//                .rememberMe() //default to 2 weeks
//                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
//                    .key("somethingverysecured")
//                    .rememberMeParameter("remember-me")
//                .and()
//                .logout()
//                    .logoutUrl("/logout")
//                    .logoutRequestMatcher(new AntPathRequestMatcher("logoutUrl","GET")) //pt ca CSRF e disable, daca e enabled atunci stergem linia asta de cod pt ca altfel ar deveni un POST
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                    .deleteCookies("JSESSIONID", "remember-me")
//                    .logoutSuccessUrl("login");

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);// allows the password to be encoded
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails annaSmithUser = User.builder()
//                .username("annasmith")
//                .password(passwordEncoder.encode("password"))
////                .roles(ApplicationUserRole.STUDENT.name()) //ROLE_STUDENT
//                .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
//                .build();
//
//        UserDetails lindaUser = User.builder()
//                .username("linda")
//                .password(passwordEncoder.encode("password123"))
////                .roles(ApplicationUserRole.ADMIN.name())
//                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails tomUser = User.builder()
//                .username("tom")
//                .password(passwordEncoder.encode("password123"))
////                .roles(ApplicationUserRole.ADMINTRAINEE.name())
//                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
//                .build();
//
//        return new InMemoryUserDetailsManager(
//                annaSmithUser,
//                lindaUser,
//                tomUser
//        );
//    }
}
