package com.ricardo.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OpenApiConfigTest {

    private final OpenApiConfig openApiConfig = new OpenApiConfig();

    @Test
    void authProviderOpenAPI_ShouldBuildExpectedMetadata() {
        OpenAPI openAPI = openApiConfig.authProviderOpenAPI();

        assertThat(openAPI).isNotNull();
        assertThat(openAPI.getInfo()).isNotNull();
        assertThat(openAPI.getInfo().getTitle()).isEqualTo("Auth Provider API");
        assertThat(openAPI.getInfo().getVersion()).isEqualTo("4.0.0");
        assertThat(openAPI.getServers()).hasSize(1);
        assertThat(openAPI.getServers().get(0).getUrl()).isEqualTo("http://localhost:8080");
    }

    @Test
    void authProviderOpenAPI_ShouldDefineCookieAuthSecurityScheme() {
        OpenAPI openAPI = openApiConfig.authProviderOpenAPI();

        SecurityScheme cookieAuth = openAPI.getComponents().getSecuritySchemes().get("CookieAuth");

        assertThat(cookieAuth).isNotNull();
        assertThat(cookieAuth.getType()).isEqualTo(SecurityScheme.Type.APIKEY);
        assertThat(cookieAuth.getIn()).isEqualTo(SecurityScheme.In.COOKIE);
        assertThat(cookieAuth.getName()).isEqualTo("access_token");
        assertThat(openAPI.getSecurity()).isNotEmpty();
        assertThat(openAPI.getSecurity().get(0).containsKey("CookieAuth")).isTrue();
    }
}
