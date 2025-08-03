package br.com.thiagomagdalena.apigateway.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import static br.com.thiagomagdalena.apigateway.security.ApiAuthenticationFilter.getVoidMono;

@Component
@Slf4j
public class JwtAuthenticationFilter implements WebFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int BEARER_PREFIX_LENGTH = BEARER_PREFIX.length();

    private final SecretKey jwtSecretKey;

    public JwtAuthenticationFilter(JwtProperties jwtProperties) {
        this.jwtSecretKey = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        Boolean authenticatedByApiKey = exchange.getAttribute(ApiAuthenticationFilter.API_KEY_AUTHENTICATED_ATTRIBUTE);
        if (Boolean.TRUE.equals(authenticatedByApiKey)) {
            log.info("Requisição para {} já autenticada por API Key. Pulando validação JWT.", path);
            return chain.filter(exchange);
        }

        if (isPublicRoute(path, request)) {
            log.info("Rota pública: {}. Pulando validação JWT.", path);
            return chain.filter(exchange);
        }

        String authorizationHeader = request.getHeaders().getFirst(AUTHORIZATION_HEADER);

        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_PREFIX)) {
            log.info("Token JWT ausente ou mal formatado para rota protegida: {}", path);
            return onError(exchange, "JWT Token is missing or malformed.", HttpStatus.UNAUTHORIZED);
        }

        String token = authorizationHeader.substring(BEARER_PREFIX_LENGTH);

        try {
            Claims claims = Jwts.parser()
                    .verifyWith(jwtSecretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String userId = claims.getSubject();
            List<String> roles = extractRoles(claims);

            log.info("JWT valido para o User ID: '{}', Roles: '{}' no caminho: {}", userId, String.join(",", roles), path);

            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-User-Id", userId)
                    .header("X-User-Roles", String.join(",", roles))
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (SignatureException e) {
            log.info("Falha na validação da assinatura JWT para o caminho '{}'. Token: {}. Erro: {}", path, truncateToken(token), e.getMessage());
            return onError(exchange, "Assinatura JWT inválida. Autenticação falhou.", HttpStatus.UNAUTHORIZED);
        } catch (MalformedJwtException e) {
            log.info("JWT malformado para o caminho '{}'. Token: {}. Erro: {}", path, truncateToken(token), e.getMessage());
            return onError(exchange, "JWT malformado. Autenticação falhou. Verifique o formato do token.", HttpStatus.BAD_REQUEST);
        } catch (ExpiredJwtException e) {
            log.info("JWT expirado para o caminho '{}'. Usuário: {}. Erro: {}", path, e.getClaims().getSubject(), e.getMessage());
            return onError(exchange, "O JWT expirou. Por favor, faça login novamente.", HttpStatus.UNAUTHORIZED);
        } catch (UnsupportedJwtException e) {
            log.info("JWT não suportado para o caminho '{}'. Token: {}. Erro: {}", path, truncateToken(token), e.getMessage());
            return onError(exchange, "Formato de JWT não suportado.", HttpStatus.UNAUTHORIZED);
        } catch (IllegalArgumentException e) {
            log.info("Argumento inválido para JWT (ex: token vazio/nulo) para o caminho '{}'. Erro: {}", path, e.getMessage());
            return onError(exchange, "JWT é inválido ou ausente.", HttpStatus.BAD_REQUEST);
        } catch (JwtException e) { // Captura qualquer outra JwtException
            log.info("Erro genérico no JWT para o caminho '{}'. Token: {}. Erro: {}", path, truncateToken(token), e.getMessage(), e);
            return onError(exchange, "Token JWT inválido. Autenticação falhou.", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) { // Captura qualquer outra exceção inesperada
            log.info("Erro inesperado no filtro JWT para o caminho '{}'. Erro: {}", path, e.getMessage(), e);
            return onError(exchange, "Ocorreu um erro inesperado durante a autenticação.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errorMessage, HttpStatus httpStatus) {
        return getVoidMono(exchange, errorMessage, httpStatus);
    }

    private boolean isPublicRoute(String path, ServerHttpRequest request) {
        if ((path.startsWith("/auth-service/users") || path.startsWith("/auth-service/users/login") ) && request.getMethod().matches("POST")) {
            return true;
        }

        return path.equals("/nasa") || path.startsWith("/nasa/")
                || path.equals("/nasa-backend") || path.startsWith("/nasa-backend/")
                || path.startsWith("/v3/api-docs") || path.startsWith("/swagger-ui")
                || path.startsWith("/.well-known/appspecific/com.chrome.devtools.json") || path.startsWith("/favicon.ico")
                || path.startsWith("/assets/") || path.startsWith("/vite.svg");
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Claims claims) {

        String rolesString = claims.get("roles", String.class);
        if (rolesString != null && !rolesString.isEmpty()) {
            return List.of(rolesString.split(","));
        }

        List<String> roles = claims.get("roles", List.class);
        if (roles != null) {
            return roles;
        }

        return Collections.emptyList();
    }

    private String truncateToken(String token) {
        if (token == null || token.length() <= 50) {
            return token;
        }
        return token.substring(0, 50) + "...";
    }
}