package be.train.demo.demo.controllers;

import be.train.demo.demo.services.SignService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
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

    @GetMapping("/sign")
    ResponseEntity<String> sign()
    {
        try
        {
            // initialize signature field parameters
            SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
            // the origin is the left and top corner of the page
            fieldParameters.setOriginX(10);
            fieldParameters.setOriginY(10);
            fieldParameters.setWidth(50);
            fieldParameters.setHeight(50);

            // Check if we can have the same field id for multiple fields
            //fieldParameters.setFieldId("some-field-id");
            File file = ResourceUtils.getFile("classpath:sample.pdf");
            DSSDocument toSignDocument = new FileDocument(file);
            DSSDocument dssDocument = signService.sign(toSignDocument, Optional.of(fieldParameters));
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }

        return ResponseEntity.ok("PDF Saved (new way) !");
    }

    @GetMapping("/client")
    ResponseEntity<String> client()
    {
        try
        {
            signService.clientSidePadesForRemoteSigning();
            return ResponseEntity.ok("Client side pades worked. Check logs");
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    @GetMapping("/doublesign")
    ResponseEntity<String> doublesign()
    {
        try
        {
            // initialize signature field parameters
            SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
            // the origin is the left and top corner of the page
            fieldParameters.setOriginX(10);
            fieldParameters.setOriginY(10);
            fieldParameters.setWidth(50);
            fieldParameters.setHeight(50);

            // Check if we can have the same field id for multiple fields
            //fieldParameters.setFieldId("some-field-id");
            File file = ResourceUtils.getFile("classpath:sample.pdf");
            DSSDocument toSignDocument = new FileDocument(file);
            DSSDocument dssDocument = signService.sign(toSignDocument, Optional.of(fieldParameters));

            fieldParameters = new SignatureFieldParameters();
            // the origin is the left and top corner of the page
            fieldParameters.setOriginX(80);
            fieldParameters.setOriginY(10);
            fieldParameters.setWidth(50);
            fieldParameters.setHeight(50);

            signService.sign(dssDocument, Optional.of(fieldParameters));
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }

        return ResponseEntity.ok("PDF Saved (double signature) !");
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
}
