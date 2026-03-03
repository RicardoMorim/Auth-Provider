package com.ricardo.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.cache.Cache;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class RedisCacheConfigTest {

    private final RedisCacheConfig redisCacheConfig = new RedisCacheConfig();

    @Test
    void redisTemplate_ShouldUseProvidedConnectionFactoryAndSerializer() {
        RedisConnectionFactory connectionFactory = mock(RedisConnectionFactory.class);

        RedisTemplate<String, Object> template = redisCacheConfig.redisTemplate(connectionFactory);

        assertThat(template.getConnectionFactory()).isEqualTo(connectionFactory);
        assertThat(template.getDefaultSerializer()).isNotNull();
    }

    @Test
    void cacheConfiguration_ShouldCreateDefaultsWithSerializerAndTtl() {
        RedisCacheConfiguration configuration = redisCacheConfig.cacheConfiguration();

        assertThat(configuration).isNotNull();
        assertThat(configuration.getAllowCacheNullValues()).isFalse();
        assertThat(configuration.getValueSerializationPair()).isNotNull();
        assertThat(configuration.getTtl()).isEqualTo(java.time.Duration.ofMinutes(60));
    }

    @Test
    void cacheManager_ShouldBuildInstance() {
        RedisConnectionFactory connectionFactory = mock(RedisConnectionFactory.class);

        RedisCacheManager cacheManager = redisCacheConfig.cacheManager(connectionFactory);

        assertThat(cacheManager).isNotNull();
        Cache cache = cacheManager.getCache("sample");
        assertThat(cache).isNotNull();
    }
}
