package com.soumen.microservices.galaryservice;

import com.netflix.hystrix.contrib.javanica.annotation.HystrixCommand;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.circuitbreaker.EnableCircuitBreaker;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@SpringBootApplication
@EnableEurekaClient
@EnableCircuitBreaker
public class GalaryServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(GalaryServiceApplication.class, args);
    }

}

@RestController
@RequiredArgsConstructor
@Log4j2
class HomeController {

    private final RestTemplate restTemplate;
    private final Environment environment;

    @GetMapping(value = "/", produces = APPLICATION_JSON_VALUE)
    public Map<String, String> home() {
        HashMap<String, String> map = new HashMap<>();
        map.put("hello", environment.getProperty("local.server.port"));
        return map;
    }

    @GetMapping(value = "/admin", produces = APPLICATION_JSON_VALUE)
    public Map<String, String> homeAdmin() {
        HashMap<String, String> map = new HashMap<>();
        map.put("hello admin", environment.getProperty("local.server.port"));
        return map;
    }

    @HystrixCommand(fallbackMethod = "fallback")
    @GetMapping(value = "/{id}", produces = APPLICATION_JSON_VALUE)
    public Gallery getGallary(@PathVariable final int id) {
        log.info("Creating gallery object ... ");
        Gallery gallery = new Gallery();
        gallery.setId(id);
        List<Image> images = restTemplate.getForObject("http://image-service/images/", List.class);
        gallery.setImages(images);
        log.info("Returning images ... ");
        return gallery;
    }

    // a fallback method to be called if failure happened
    public Gallery fallback(int galleryId, Throwable hystrixCommand) {
        return new Gallery(galleryId);
    }
}

@Data
@AllArgsConstructor
class Image {
    private Integer id;
    private String title;
    private String url;

}

@Data
@NoArgsConstructor
class Gallery {
    private int id;
    private List<Image> images;

    public Gallery(int id) {
        this.id = id;
    }
}

@Configuration
class RestTemplateConfig {
    @Bean
    @LoadBalanced
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
