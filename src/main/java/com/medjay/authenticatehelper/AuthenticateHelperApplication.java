package com.medjay.authenticatehelper;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
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
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Key;
import java.util.*;
import java.util.function.Function;
import java.util.logging.Logger;

import static com.medjay.authenticatehelper.AuthErrorCodes.*;
import static java.lang.Boolean.TRUE;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@SpringBootApplication
public class AuthenticateHelperApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthenticateHelperApplication.class, args);
    }

}


/**
 * Simple test to test authentication
 *
 * @author calvinshio(medjay)
 */
@RestController
@RequestMapping("/test-auth")
@ResponseBody
@ResponseStatus(HttpStatus.ACCEPTED)
class AuthTestController {
    private final Logger logger = Logger.getLogger(AuthTestController.class.getName());

    @PreAuthorize("hasAnyAuthority('RESET_PASS')")
    @GetMapping("/hello-world")
    public String helloWorld() {
        // initiate logger
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        logger.info("auth-hello-world authenticated user: " + authentication.getName() + " With authorities: " + authentication.getAuthorities());
        return "Hello World";
    }
}


/**
 * This is the main configuration that will utilize the custom filter
 * for any public url add then in the public urls field in props
 * please note I have enabled method security
 *
 * @author calvinshio(medjay)
 * @see JwtFilter
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfiguration {
    private final JwtFilter jwtFilter;
    @Value("${authentication.open-urls}")
    private String[] urlsPublic;

    SecurityConfiguration(JwtFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    // global authentication manager
    @Bean
    AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        return new ProviderManager(daoAuthenticationProvider);
    }

    // web-security config
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                // add public urls
                .authorizeHttpRequests(req -> req.requestMatchers(urlsPublic)
                        .permitAll()
                        // reset authentication
                        .anyRequest()
                        .authenticated())
                // stateless authentication
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                // pass auth filter before
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}

/**
 * Main Part of the authentication process that uses OncePerRequestFilter web filter
 * All requests will be passed through and validated in they contain an authorization header that starts with an
 * agreed acronym in this example "Bearer ", all other headers are ignored in case your want some end-point to have
 * a different validation scheme.
 *
 * @author calvinshio(medjay)
 * @version 1.0
 * @see OncePerRequestFilter
 */
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
            try {
                // get username from token
                String username = jwtService.extractUserFromToken(token);
                logger.info("Username From Auth Header Extracted: " + username);
                // check username could be extracted from the token and
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
            } catch (SignatureException | ExpiredJwtException exception) {
                // means tokens are invalid --> return response
                ObjectMapper mapper = new ObjectMapper();
                AuthErrorResponse authErrorResponse = new AuthErrorResponse(
                        INVALID_TOKEN.getCode(),
                        INVALID_TOKEN.getMessage(),
                        exception.getMessage()
                );
                response.setStatus(INVALID_TOKEN.getHttpStatus().value());
                response.setContentType("application/json");
                response.getWriter().write(mapper.writeValueAsString(authErrorResponse));
                // terminate filter chain and return response
                return;
            } catch (KeyException | SecurityException exception) {
                // means tokens are invalid --> return response
                ObjectMapper mapper = new ObjectMapper();
                AuthErrorResponse authErrorResponse = new AuthErrorResponse(
                        INVALID_KEY.getCode(),
                        INVALID_KEY.getMessage(),
                        exception.getMessage()
                );
                response.setStatus(INVALID_KEY.getHttpStatus().value());
                response.setContentType("application/json");
                response.getWriter().write(mapper.writeValueAsString(authErrorResponse));
                // terminate filter chain and return response
                return;
            } catch (Exception exception) {
                // means tokens are invalid --> return response
                ObjectMapper mapper = new ObjectMapper();
                AuthErrorResponse authErrorResponse = new AuthErrorResponse(
                        NO_CODE.getCode(),
                        NO_CODE.getMessage(),
                        exception.getMessage()
                );
                response.setStatus(INVALID_KEY.getHttpStatus().value());
                response.setContentType("application/json");
                response.getWriter().write(mapper.writeValueAsString(authErrorResponse));
                // terminate filter chain and return response
                return;
            }
        }
        // return request to the filter chain
        filterChain.doFilter(request, response);
    }
}


/**
 * Fetch Permissions from redis store please note that the key used is the username of a user
 * implementation using spring-data-redis
 * redis-host and port should be defined in the props file
 *
 * @author calvinshio(medjay)
 */
@Service
class RedisService {
    @Value("${authentication.redis.host-name}")
    public String redisHost;
    @Value("${authentication.redis.port}")
    public int redisPort;

    // get stored permissions from redis
    public Set<String> getUserPermissionFromRedis(String username) throws DefaultAuthException {
        // initiate redis template
        RedisTemplate<String, RedisUserPerms> authRedisTemplate = getAuthRedisTemplate();
        RedisUserPerms redisUserPerms = authRedisTemplate.opsForValue().get(username);
        if (redisUserPerms != null && !redisUserPerms.permissions.isEmpty()) {
            return new HashSet<>(redisUserPerms.permissions);
        } else {
            // if no permissions found
            throw new DefaultAuthException("No Permissions For Your Account Were Found");
        }
    }

    // redis template init with a custom Jackson2JsonRedisSerializer for my object
    private RedisTemplate<String, RedisUserPerms> getAuthRedisTemplate() {
        Jackson2JsonRedisSerializer<RedisUserPerms> jackson2JsonRedisSerializer = new Jackson2JsonRedisSerializer<>(RedisUserPerms.class);
        RedisTemplate<String, RedisUserPerms> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(getLettuceConnectionFactory());
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(jackson2JsonRedisSerializer);
        redisTemplate.afterPropertiesSet();
        return redisTemplate;
    }

    // make redis stand-alone connection factory without global configuration
    private LettuceConnectionFactory getLettuceConnectionFactory() {
        RedisStandaloneConfiguration redisStandaloneConfiguration = new RedisStandaloneConfiguration();
        redisStandaloneConfiguration.setHostName(redisHost);
        redisStandaloneConfiguration.setPort(redisPort);
        LettuceConnectionFactory connectionFactory = new LettuceConnectionFactory(redisStandaloneConfiguration);
        // connection factory need to be initialized
        connectionFactory.start();
        return connectionFactory;
    }

    // redis object serialized by my version of token authentication
    record RedisUserPerms(
            String username,
            List<String> permissions
    ) {
    }
}


/**
 * implementation of Authentication spring security model through AbstractAuthenticationToken for security
 * context
 *
 * @author calvinshio(medjay)
 * @see AbstractAuthenticationToken
 */
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


/**
 * error codes used in the token authentication process mapping to http-server responses
 *
 * @author calvinshio(medjay)
 * @see AuthErrorResponse
 */
enum AuthErrorCodes {
    NO_CODE(0, "An Error occurred while authentication your token", HttpStatus.BAD_REQUEST),
    INVALID_KEY(1, "Invalid JWT keys", HttpStatus.BAD_REQUEST),
    INVALID_TOKEN(2, "Invalid JWT Token", HttpStatus.FORBIDDEN),
    ;
    private final int code;
    private final String message;
    private final HttpStatus httpStatus;

    AuthErrorCodes(int code, String message, HttpStatus httpStatus) {
        this.code = code;
        this.message = message;
        this.httpStatus = httpStatus;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}

/**
 * Custom error response object for user-friendlier errors
 *
 * @param errorCode   error-id in simple terms
 * @param description custom error message which you can customise
 * @param error       exception message
 * @author calvinshio(medjay)
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
record AuthErrorResponse(
        int errorCode,
        String description,
        String error
) {
}

class DefaultAuthException extends Exception {
    public DefaultAuthException(String message) {
        super(message);
    }
}


/**
 * Jwt Service dealing with extracting claims from provided token
 * please make sure you provide a secret key in your props file
 *
 * @author calvinshio(medjay)
 * @version 1.0
 * @see io.jsonwebtoken for more details on how tokens are taken and verified
 */
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