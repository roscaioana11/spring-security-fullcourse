package com.example.springsecurityfullcourse.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
@RequestMapping("/")
public class TemplateController {

    @GetMapping("login")
    public String getLoginView(){
        return "login"; //trebuie sa fie exact acelasi nume pe care il aveam in templates dar fata .html
    }

    @GetMapping("courses")
    public String getCourses(){
        return "courses"; //trebuie sa fie exact acelasi nume pe care il aveam in templates dar fata .html
    }
}
