package med.voll.web_application.infra.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class ConfiguracoesSeguranca {

    @Bean
    public SecurityFilterChain filtrosSeguranca(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(req -> {
            req.requestMatchers("/css/**", "/js/**", "/assets/**").permitAll(); // recursos permitidos a estas reqs
            req.anyRequest().authenticated(); // bloqueia todoo restante
        })
        .formLogin(form -> form.loginPage("/login")
            .defaultSuccessUrl("/")
            .permitAll()) // login permitido a todas as requisições
        .logout(logout -> logout.logoutSuccessUrl("/login?logout")
            .permitAll()) // redirecionamento de logout permitido a todas as requisições
        .rememberMe(rememberMe ->
                rememberMe.key("secretKeyProtegerNoConfigServer"))
                // .csrf()
        .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
