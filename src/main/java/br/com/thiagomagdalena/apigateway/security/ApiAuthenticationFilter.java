package br.com.thiagomagdalena.apigateway.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class ApiAuthenticationFilter implements WebFilter {

    private static final String API_KEY_HEADER = "X-API-Key";
    public static final String API_KEY_AUTHENTICATED_ATTRIBUTE = "api_key_authenticated";
    private static final String ADMIN_ROLE = "ROLE_ADMINISTRATOR";

    private final ApiKeysProperties apiKeysProperties;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        Optional<String> apiKeyHeader = Optional.ofNullable(request.getHeaders().getFirst(API_KEY_HEADER));

        if (apiKeyHeader.isEmpty()) {
            return chain.filter(exchange);
        }

        String providedApiKey = apiKeyHeader.get();

        if (apiKeysProperties.getValidApiKeys().contains(providedApiKey)) {
            log.debug("API Key válida. A adicionar header de admin.");
            exchange.getAttributes().put(API_KEY_AUTHENTICATED_ATTRIBUTE, true);
            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-User-Roles", ADMIN_ROLE)
                    .build();
            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        } else {
            log.warn("API Key inválida para rota: {}. Chave fornecida: {}", path, providedApiKey);
            return onError(exchange, "Invalid API Key.", HttpStatus.UNAUTHORIZED);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errorMessage, HttpStatus httpStatus) {
        return getVoidMono(exchange, errorMessage, httpStatus);
    }

    static Mono<Void> getVoidMono(ServerWebExchange exchange, String errorMessage, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String errorJson = String.format(
                "{\"status\": %d, \"error\": \"%s\", \"message\": \"%s\", \"timestamp\": \"%s\"}",
                httpStatus.value(), httpStatus.getReasonPhrase(), errorMessage, java.time.Instant.now().toString()
        );

        return response.writeWith(Mono.just(response.bufferFactory().wrap(errorJson.getBytes(StandardCharsets.UTF_8))));
    }
}