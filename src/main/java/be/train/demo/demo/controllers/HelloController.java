package be.train.demo.demo.controllers;

import be.train.demo.demo.common.CertificateDER;
import be.train.demo.demo.dtos.eid.*;
import be.train.demo.demo.services.SignService;
import be.train.demo.demo.utils.SignatureAlgorithmMapper;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.util.Base64;
import java.util.Optional;

@RestController("/java/")
public class HelloController
{
    @Autowired
    SignService signService;

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

    @PostMapping("/signatures/eid/prepare")
    ResponseEntity<SignaturePreparationResponseDTO> prepareSignature(@Valid @RequestBody SignaturePreparationRequestDTO signaturePrepareRequest)
    {
        try
        {
            CertificateDER certificateDer = new CertificateDER(signaturePrepareRequest.getCertificateBase64());
            CertificateToken certificateToken = new CertificateToken(certificateDer.convertToX509Certificate());
            SignaturePreparationResponseDTO signaturePreparationResponseDTO = new SignaturePreparationResponseDTO();

            Digest digest = signService.prepareSignature(certificateToken);
            String digestAlgorithm = SignatureAlgorithmMapper.getDigestAlgorithm(signService.getDefaultDigestAlgorithm());

            signaturePreparationResponseDTO.setHashValue(digest.getBase64Value());
            signaturePreparationResponseDTO.setHashFunction(digestAlgorithm);

            return ResponseEntity.ok(signaturePreparationResponseDTO);
        }
        catch (Exception e)
        {
            return ResponseEntity.badRequest().body(new SignaturePreparationResponseDTO());
        }
    }

    @PostMapping("/signatures/eid/finalize")
    ResponseEntity<SignatureFinalizeResponseDTO> finalizeSignature(@Valid @RequestBody SignatureFinalizeRequestDTO signatureRequest)
    {
        try
        {
            SignatureValue signature = new SignatureValue();
            byte[] signatureBytes = Base64.getDecoder().decode(signatureRequest.getSignatureBase64());

            SignatureAlgorithmDTO signatureAlgorithmDTO = signatureRequest.getSignatureAlgorithmDTO();
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithmMapper.from(signatureAlgorithmDTO.getCryptoAlgorithm(), signatureAlgorithmDTO.getHashFunction());

            signature.setValue(signatureBytes);
            signature.setAlgorithm(signatureAlgorithm);

            signService.finalizeSignature(signature);

            return ResponseEntity.ok(new SignatureFinalizeResponseDTO("Signature Finalized!", true));
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
            return ResponseEntity.badRequest().body(new SignatureFinalizeResponseDTO("La signature n'a pas été finalisée", false));
        }
    }

    @PostMapping("/signatures/itsme")
    ResponseEntity<String> prep()
    {
        return ResponseEntity.ok("gg");
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
