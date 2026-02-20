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
import org.springframework.web.bind.annotation.*;

import javax.swing.text.html.Option;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

@RestController
public class HelloController
{
    @Autowired
    SignService signService;

    @GetMapping("signature/{p12name}/{p12pass}")
    ResponseEntity<String> signature(@PathVariable String p12name, @PathVariable String p12pass)
    {
        try
        {
            signService.PushCertificateForDemo(p12name, p12pass);
            // initialize signature field parameters
            SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
            // the origin is the left and top corner of the page
            fieldParameters.setOriginX(10);
            fieldParameters.setOriginY(10);
            fieldParameters.setWidth(50);
            fieldParameters.setHeight(50);

            //File file = ResourceUtils.getFile("classpath:sample.pdf");
            File file = new File("sample.pdf");
            DSSDocument toSignDocument = new FileDocument(file);
            DSSDocument dssDocument = signService.sign(toSignDocument, Optional.of(fieldParameters));
        }
        catch (Exception e)
        {
            return ResponseEntity.ok(e.toString() + "<br>\nLe nom du certificat et/ou le mot de passe sont incorrects. Le certificat doit aussi se trouver dans le meme dossier que l'executable java");
        }
        finally
        {
            signService.PopCertificateForDemo();
        }

        return ResponseEntity.ok("PDF signé avec succès!");
    }

    @GetMapping("/sign")
    ResponseEntity<String> sign()
    {
        try
        {
            signService.PushCertificateForDemo("self-signed.p12", "changeit");
            // initialize signature field parameters
            SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
            // the origin is the left and top corner of the page
            fieldParameters.setOriginX(10);
            fieldParameters.setOriginY(10);
            fieldParameters.setWidth(50);
            fieldParameters.setHeight(50);

            File file = new File("sample.pdf");
            DSSDocument toSignDocument = new FileDocument(file);
            DSSDocument dssDocument = signService.sign(toSignDocument, Optional.of(fieldParameters));
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
        finally
        {
            signService.PopCertificateForDemo();
        }

        return ResponseEntity.ok("PDF Signed!");
    }

    @GetMapping("/client")
    ResponseEntity<String> client()
    {
        try
        {
            signService.PushCertificateForDemo("self-signed.p12", "changeit");
            signService.clientSidePadesForRemoteSigning();
            return ResponseEntity.ok("Client side pades worked");
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
        finally
        {
            signService.PopCertificateForDemo();
        }
    }

    @GetMapping("/doublesign")
    ResponseEntity<String> doublesign()
    {
        try
        {
            signService.PushCertificateForDemo("self-signed.p12", "changeit");

            // initialize signature field parameters
            SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
            // the origin is the left and top corner of the page
            fieldParameters.setOriginX(10);
            fieldParameters.setOriginY(10);
            fieldParameters.setWidth(50);
            fieldParameters.setHeight(50);

            // Check if we can have the same field id for multiple fields
            //fieldParameters.setFieldId("some-field-id");
            File file = new File("sample.pdf");
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
        finally
        {
            signService.PopCertificateForDemo();
        }

        return ResponseEntity.ok("PDF Saved (double signature) !");
    }
}
