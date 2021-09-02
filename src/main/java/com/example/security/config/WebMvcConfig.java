package com.example.security.config;



import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import java.util.Arrays;


/**
 * Front-end Client에서 server의  API에 access할 수 있또록 cors를 Open합니다
 */
@Configuration
public class WebMvcConfig  {

    @Bean
    public CorsFilter corsFilter(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // 내 서버가 응답을 할 때 json을 자바스크립트에서 처리할 수 있게 할지를 설정하는 것 그래서 true로 해줌
//        config.setAllowedOriginPatterns(Arrays.asList("*")); // 모든 ip에 응답을 허용하겠다.
        config.setAllowedOrigins(Arrays.asList("*"));
        config.addAllowedHeader("*"); // 모든 header에 응답을 허용하겠다.

        config.addAllowedMethod("*"); // 모든 post,get,delete,update 허용
        config.setExposedHeaders(Arrays.asList("Authorization", "Content-Type"));
        source.registerCorsConfiguration("/**",config);
        return new CorsFilter(source);
    }
}