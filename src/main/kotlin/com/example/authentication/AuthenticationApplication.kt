package com.example.authentication

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal


@EnableResourceServer
@SpringBootApplication
class AuthenticationApplication

fun main(args: Array<String>) {
    SpringApplication.run(AuthenticationApplication::class.java, *args)
}


@RestController
class PrincipalRestController {

    @RequestMapping("/user")
    fun principal(principal: Principal) = principal
}

@Configuration
@EnableAuthorizationServer
internal class OAuthConfiguration(private val authenticationManager: AuthenticationManager) : AuthorizationServerConfigurerAdapter() {

    @Throws(Exception::class)
    override fun configure(clients: ClientDetailsServiceConfigurer) {
        clients.inMemory()
                .withClient("html5")
                .scopes("openid")
                .secret("password")
                .authorizedGrantTypes("password")
    }

    @Throws(Exception::class)
    override fun configure(endpoints: AuthorizationServerEndpointsConfigurer?) {
        endpoints!!.authenticationManager(this.authenticationManager)
    }
}

@Service
internal class AccountUserDetailsService : UserDetailsService {

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(username: String) =
            User(username, username, AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER"))
}