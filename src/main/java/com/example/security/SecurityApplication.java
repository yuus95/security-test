package com.example.security;

import com.example.security.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;


/**
 * @EnableConfigurationProperties
 * JWT Configuation을 binding하는 POJO클래스를 프로젝트에 적용시키게 해준다.
 */
@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

}
