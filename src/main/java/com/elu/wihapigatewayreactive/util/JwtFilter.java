package com.elu.wihapigatewayreactive.util;

import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtFilter implements WebFilter {

    private JwtUtil jwtUtil;
    private AntPathMatcher pathMatcher = new AntPathMatcher();

    public JwtFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    private static final List<String> PUBLIC_URLS = List.of(
            "/auth/**",
            "/actuator/**"
    );

    private static final Logger log = LoggerFactory.getLogger(JwtFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        String method = exchange.getRequest().getMethod().toString();

        log.debug("Incoming request - [{}] {}", method, path);

        // Allow OPTIONS requests (CORS preflight)
        if ("OPTIONS".equalsIgnoreCase(method)) {
            log.debug("CORS preflight detected (OPTIONS) - skipping filter.");
            return chain.filter(exchange);
        }

        // Skip public URLs
        boolean isPublicPath = PUBLIC_URLS.stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path));

        if (isPublicPath) {
            log.debug("Public endpoint detected - [{}], skipping JWT validation", path);
            return chain.filter(exchange);
        }

        // Try to get token from Authorization header
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        String token = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            log.debug("JWT found in Authorization header.");
        } else {
            // Try to read from cookies
            var cookies = exchange.getRequest().getCookies().get("jwt");
            if (cookies != null && !cookies.isEmpty()) {
                token = cookies.get(0).getValue();
                log.debug("JWT found in cookies.");
            } else {
                log.warn("No JWT token found in request headers or cookies.");
            }
        }

        // Validate token
        if (token == null || !jwtUtil.validateToken(token)) {
            log.warn("Invalid or missing JWT token for request path: {}", path);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Extract authentication info
        String email = jwtUtil.extractEmail(token);
        var roles = jwtUtil.extractRoles(token);

        log.info("Authenticated user: {} with roles: {}", email, roles);

        var authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        var auth = new UsernamePasswordAuthenticationToken(email, null, authorities);

        // Put authentication in reactive SecurityContext
        return chain.filter(exchange)
                .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                        Mono.just(new SecurityContextImpl(auth))
                ));
    }
}
