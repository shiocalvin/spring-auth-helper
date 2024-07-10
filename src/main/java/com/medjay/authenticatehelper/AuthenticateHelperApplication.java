package com.medjay.authenticatehelper;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.file.attribute.UserPrincipal;
import java.security.Key;
import java.security.Principal;
import java.time.LocalDateTime;
import java.util.*;
import java.util.function.Function;
import java.util.logging.Logger;

import static java.lang.Boolean.TRUE;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@SpringBootApplication
public class AuthenticateHelperApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthenticateHelperApplication.class, args);
    }

}

// test-controller auth works?
@RestController
@RequestMapping("/test-auth")
@ResponseBody
@ResponseStatus(HttpStatus.ACCEPTED)
class AuthTestController {
    @GetMapping("/hello-world")
    public String helloWorld() {
        return "Hello World";
    }
}

@Configuration
@EnableWebSecurity
class SecurityConfiguration {
    private final JwtFilter jwtFilter;
    @Value("${authentication.open-urls}")
    private String[] urlsPublic;
    private final UserDetailsService userDetailsService;

    SecurityConfiguration(JwtFilter jwtFilter, UserDetailsService userDetailsService) {
        this.jwtFilter = jwtFilter;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        return new ProviderManager(daoAuthenticationProvider);
    }

    // web-security config
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                // add public urls
                .authorizeHttpRequests(req -> {
                    req.requestMatchers(urlsPublic)
                            .permitAll()
                            // reset authentication
                            .anyRequest()
                            .authenticated();
                })
//                .httpBasic(Customizer.withDefaults())
                // stateless authentication
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                // pass auth filter before
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}

// request filter
@Service
class JwtFilter extends OncePerRequestFilter {
    @Value("${authentication.header-acronym}")
    private String headerAcronym;
    private final JwtService jwtService;
    private final RedisService redisService;

    // instantiate logger
    private final static Logger logger = Logger.getLogger(JwtFilter.class.getName());

    JwtFilter(JwtService jwtService, RedisService redisService) {
        this.jwtService = jwtService;
        this.redisService = redisService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        logger.info("Request For URI: " + request.getRequestURI() + " Method: " + request.getMethod() + " Passed Through Auth Filter");
        // get authorization header from request use authorization header from spring-boot
        final String authorizationHeader = request.getHeader(AUTHORIZATION);
        logger.info("Authorization Header: " + authorizationHeader);
        // check if auth header is present and start with agreed header acronym
        if (authorizationHeader != null && authorizationHeader.startsWith(headerAcronym)) {
            logger.info("Valid Authorization Header Format: " + authorizationHeader);
            // get token without header
            String token = authorizationHeader.substring(headerAcronym.length()).trim();
            // get username from token
            String username = jwtService.extractUserFromToken(token);
            logger.info("Username From Auth Header Extracted: " + username);
            // check username could be extracted from the token and
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (username != null & SecurityContextHolder.getContext().getAuthentication() == null) {
                // means user-name found and no authentication context was found
                logger.info("Request Has No Authentication Context");
                // check if token is valid
                if (jwtService.isTokenValid(token)) {
                    logger.info("Request Token is Valid");
                    // make new user-details?--> get from redis
                    Set<String> permissions = redisService.getUserPermissionFromRedis(username);
                    // permissions obtained from redis
                    logger.info("Permissions For User Obtained From Redis: " + permissions);
                    // make custom authentication object
                    UserAuthenticationToken userAuthenticationToken = new UserAuthenticationToken(username,
                            username,
                            permissions.stream().map(SimpleGrantedAuthority::new).toList()
                    );
                    // set authenticated
                    userAuthenticationToken.setAuthenticated(TRUE);
                    // set user authentication context
                    SecurityContextHolder.getContext().setAuthentication(userAuthenticationToken);
                    logger.info("Request Has Been Validated And Authentication Context Has Been Added");
                } else {
                    logger.warning("Token For Request " + request.getRequestURI() + " is invalid ");
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}

@Service
class JwtService {
    @Value("${authentication.secret-key}")
    private String secretKey;

    // function to check if token is valid
    public boolean isTokenValid(String token) {
        return isTokenExpired(token);
    }

    // extract user-name from token
    public String extractUserFromToken(String token) {
        return extractClaimsFromToken(token, Claims::getSubject);
    }

    // check if token has expired
    private boolean isTokenExpired(String token) {
        // invert the dates checks
        return !extractExpirationDateFromToken(token).before(new Date());
    }

    // get token expiry date
    private Date extractExpirationDateFromToken(String token) {
        return extractClaimsFromToken(token, Claims::getExpiration);
    }

    //get single claim from token like user-name
    private <T> T extractClaimsFromToken(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaimsFromToken(token);
        return claimResolver.apply(claims);
    }

    // extract all claims from token
    private Claims extractAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // get key for token verification
    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}


@Service
class RedisService {
    @Value("${authentication.redis.host-name}")
    public String redisHost;
    @Value("${authentication.redis.port}")
    public int redisPort;
    // get permissions
    public Set<String> getUserPermissionFromRedis(String username) {
        // initiate redis template
        RedisTemplate<String, RedisUserPerms> authRedisTemplate = getAuthRedisTemplate();
        RedisUserPerms redisUserPerms = authRedisTemplate.opsForValue().get(username);
        if (redisUserPerms != null) {
            return new HashSet<>(redisUserPerms.permissions);
        } else {
            return new HashSet<>();
        }
    }


    private RedisTemplate<String, RedisUserPerms> getAuthRedisTemplate() {
        Jackson2JsonRedisSerializer<RedisUserPerms> jackson2JsonRedisSerializer = new Jackson2JsonRedisSerializer<>(RedisUserPerms.class);
        RedisTemplate<String, RedisUserPerms> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(getLettuceConnectionFactory());
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(jackson2JsonRedisSerializer);
        redisTemplate.afterPropertiesSet();
        return redisTemplate;
    }

    private LettuceConnectionFactory getLettuceConnectionFactory() {
        RedisStandaloneConfiguration redisStandaloneConfiguration = new RedisStandaloneConfiguration();
        redisStandaloneConfiguration.setHostName(redisHost);
        redisStandaloneConfiguration.setPort(redisPort);
        LettuceConnectionFactory connectionFactory = new LettuceConnectionFactory(redisStandaloneConfiguration);
        // connection factory need to be initialized?
        connectionFactory.start();
        return connectionFactory;
    }

    record RedisUserPerms(
            String username,
            List<String> permissions
    ) {
    }
}

@Service
class HelperUserDetailsService implements UserDetailsService {
    private final RedisService redisService;

    HelperUserDetailsService(RedisService redisService) {
        this.redisService = redisService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // find user-details from redis and make user details
        Set<String> userPermissionFromRedis = redisService.getUserPermissionFromRedis(username);
        return new userRecord(username, userPermissionFromRedis.stream().toList());
    }

    record userRecord(String username, List<String> permissions) implements UserDetails, Principal {

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            permissions.forEach(p -> authorities.add(new SimpleGrantedAuthority(p)));
            return authorities;
        }

        @Override
        public String getPassword() {
            return "";
        }

        @Override
        public String getUsername() {
            return username;
        }

        @Override
        public String getName() {
            return username;
        }
    }
}

class UserAuthenticationToken extends AbstractAuthenticationToken {
    private final Object principal;
    private final Object credentials;

    public UserAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}


// TODO exception handling --> ExpiredJwtException for token expiry