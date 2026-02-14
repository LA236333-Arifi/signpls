package be.train.demo.demo.controllers;

import be.train.demo.demo.services.SignService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.swing.text.html.Option;
import java.io.File;
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

    @GetMapping("/pen")
    ResponseEntity<String> pen()
    {
        try
        {
            signService.pen();
            return ResponseEntity.ok("Pen saved !");
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/doublepen")
    ResponseEntity<String> doublepen()
    {
        try
        {
            signService.doublepen();
            return ResponseEntity.ok("Double Pen saved !");
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/sign")
    ResponseEntity<String> sign()
    {
        try
        {
            File file = ResourceUtils.getFile("classpath:sample.pdf");
            DSSDocument toSignDocument = new FileDocument(file);
            DSSDocument dssDocument = signService.sign(toSignDocument, Optional.empty());
            signService.sign(dssDocument, Optional.empty());
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
    public ResponseEntity<String> query()
    {
        try
        {
            return ResponseEntity.ok(signService.querySomeData().isEmpty() ? "Empty" : signService.querySomeData().getFirst());
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }
}
