package com.pupscan.authentication

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
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
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal
import javax.servlet.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


@EnableResourceServer
@SpringBootApplication
class AuthenticationApplication

fun main(args: Array<String>) {
    SpringApplication.run(AuthenticationApplication::class.java, *args)
}

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class Cors : Filter {
    override fun doFilter(req: ServletRequest, resp: ServletResponse, chain: FilterChain) {
        val response = resp as HttpServletResponse
        val request = req as HttpServletRequest
        response.setHeader("Access-Control-Allow-Origin", "*")
        response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")
        response.setHeader("Access-Control-Max-Age", "3600")
        response.setHeader("Access-Control-Allow-Headers", "x-requested-with, authorization, Content-Type, Authorization, credential, X-XSRF-TOKEN")

        if ("OPTIONS".equals(request.method, ignoreCase = true)) {
            response.status = HttpServletResponse.SC_OK
        } else {
            chain.doFilter(req, resp)
        }
    }

    override fun init(p0: FilterConfig?) {}
    override fun destroy() {}
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
    override fun loadUserByUsername(username: String): User {
        if (username.contains("@pupscan.com")) {
            return User(username, "pupscan", AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER"))
        }
        throw UsernameNotFoundException("Not found")
    }
}
