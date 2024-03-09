package com.example.OAuthJwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyController {
    @GetMapping("/my")
    public String myApi(){
        return "my route";
    }
}
