package com.soumen.microservices.galaryservice;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
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
public class GalaryServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(GalaryServiceApplication.class, args);
    }

}

@RestController
@RequiredArgsConstructor
class HomeController {

    private final RestTemplate restTemplate;
    private final Environment environment;

    @GetMapping(value = "/",produces = APPLICATION_JSON_VALUE)
    public Map<String, String> home() {
        HashMap<String, String> map = new HashMap<>();
        map.put("hello", environment.getProperty("local.server.port"));
        return map;
    }

    @GetMapping(value="/admin",produces = APPLICATION_JSON_VALUE)
    public Map<String, String> homeAdmin() {
        HashMap<String, String> map = new HashMap<>();
        map.put("hello admin", environment.getProperty("local.server.port"));
        return map;
    }

    @GetMapping(value = "/{id}",produces = APPLICATION_JSON_VALUE)
	public Gallery getGallary(@PathVariable final int id){
		Gallery gallery = new Gallery();
		gallery.setId(id);
		List<Image> images = restTemplate.getForObject("http://image-service/images/", List.class);
		gallery.setImages(images);
		return gallery;
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
class Gallery{
	private int id;
	private List<Image> images;
}

@Configuration
class RestTemplateConfig {
    @Bean
    @LoadBalanced
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
