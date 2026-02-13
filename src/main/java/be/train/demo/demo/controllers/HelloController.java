package be.train.demo.demo.controllers;

import be.train.demo.demo.services.SignService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/hello")
public class HelloController
{
    @Autowired
    SignService signService;

    @GetMapping("/cook")
    ResponseEntity<String> cook()
    {
        try
        {
            String s = signService.cook();
            return ResponseEntity.ok(s);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/dbl")
    ResponseEntity<String> dbl()
    {
        try
        {
            signService.dbl();
            return ResponseEntity.ok("PDF DOUBLE SIGNED");
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/wow")
    ResponseEntity<String> wow()
    {
        try
        {
            signService.wow();
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }

        return ResponseEntity.ok("PDF Saved (new way) !");
    }

    @GetMapping("/keystore")
    ResponseEntity<String> keystore()
    {
        try
        {
            String s = signService.keystore();
            return ResponseEntity.ok(s);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/query")
    public ResponseEntity<List<String>> query()
    {
        try
        {
            return ResponseEntity.of(Optional.ofNullable(signService.querySomeData()));
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }
}
