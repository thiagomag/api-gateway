package br.com.thiagomagdalena.apigateway.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix = "api.keys")
@Getter
@Setter
public class ApiKeysProperties {
    private List<String> validApiKeys;
}