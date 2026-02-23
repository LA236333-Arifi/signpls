package be.train.demo.demo.controllers;

import be.train.demo.demo.dtos.CertificateDTO;
import be.train.demo.demo.dtos.SignatureFinalizeRequestDTO;
import be.train.demo.demo.services.SignService;
import be.train.demo.demo.utils.SignatureAlgorithmMapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import jakarta.validation.Valid;
import org.apache.coyote.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Base64;
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

    @GetMapping("/signatures/prepare")
    ResponseEntity<String> prepareSignature(@Valid @RequestBody CertificateDTO certificateDTO)
    {
        try
        {
            CertificateToken certificateToken = new CertificateToken(certificateDTO.toX509Certificate());
            signService.PrepareSignature(certificateToken);
            return ResponseEntity.ok("Signature prepared!");
        }
        catch (Exception e)
        {
            return ResponseEntity.badRequest().body("Certificat X509 invalide ou manquant.");
        }
    }

    @PostMapping("/signatures/finalize")
    ResponseEntity<String> finalizeSignature(@Valid @RequestBody SignatureFinalizeRequestDTO signatureRequest)
    {
        try
        {
            SignatureValue signature = new SignatureValue();
            byte[] signatureBytes = Base64.getDecoder().decode(signatureRequest.getSignatureBase64());

            EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.valueOf(signatureRequest.getSignatureAlgorithmDTO().getCryptoAlgorithm());
            DigestAlgorithm digestAlgorithm = DigestAlgorithm.valueOf(signatureRequest.getSignatureAlgorithmDTO().getHashFunction());
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithmMapper.from(encryptionAlgorithm, digestAlgorithm);

            signature.setValue(signatureBytes);
            signature.setAlgorithm(signatureAlgorithm);

            signService.FinalizeSignature(signature);

            return ResponseEntity.ok("Signature Finalized!");
        }
        catch (Exception e)
        {
            return ResponseEntity.badRequest().body("La signature n'a pas été finalisée");
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
