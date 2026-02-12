package be.train.demo.demo.controllers;

import be.train.demo.demo.services.SignService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/hello")
public class HelloController
{
    @Autowired
    SignService signService;

    @GetMapping()
    ResponseEntity<String> processHello()
    {
        try
        {
            signService.newSign();
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }

        return ResponseEntity.ok("PDF Saved !");
    }
}
