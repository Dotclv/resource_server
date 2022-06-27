package com.example;

import com.alibaba.fastjson.JSON;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@SpringBootApplication
@ComponentScan(basePackages = {"com"})
@RestController

public class App {


    @RequestMapping("/test/health")
    public String te(Authentication authentication){
        Object principal = authentication.getPrincipal();
        System.out.println(JSON.toJSONString(authentication));
        return "1";
    }
    @RequestMapping("/test/tes")
    public String tes(Authentication authentication){
        Object principal = authentication.getPrincipal();
        System.out.println(JSON.toJSONString(authentication));
        return "1";
    }
    @RequestMapping("/tes")
    public String tess(){
        return "1";
    }
    @RequestMapping("/tesc")
    public String tescs(){
        return "1";
    }
    public static void main(String[] args) throws IOException {
        SpringApplication.run(App.class);
        //System.out.println("11");
    }

}