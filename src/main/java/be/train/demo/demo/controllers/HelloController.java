package be.train.demo.demo.controllers;

import be.train.demo.demo.common.CertificateDER;
import be.train.demo.demo.dtos.eid.*;
import be.train.demo.demo.models.*;
import be.train.demo.demo.services.SignService;
import be.train.demo.demo.utils.SignatureAlgorithmMapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.*;

@RestController()
@RequestMapping("/SignElec")
public class HelloController
{
    @Autowired
    SignService signService;

    @PostMapping("/java/signatures/sbim")
    ResponseEntity<?> SignSimpleSbim(@Valid @RequestBody SimpleSignatureRequest signatureParams)
    {
        try
        {
            String pdfBase64 = signatureParams.getSignatureParameters().getPdfBase64();
            byte[] pdfFile = Base64.getDecoder().decode(pdfBase64);

            DSSDocument toSignDocument = new InMemoryDocument(pdfFile);
            SignOutput signOutput = signService.sign(toSignDocument, Optional.empty());

            SimpleSignatureResponse response = new SimpleSignatureResponse();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            DSSDocument signedDocument = signOutput.getSignedDocument();
            SignatureValue signatureValue = signOutput.getSignatureValue();

            signedDocument.writeTo(outputStream);
            byte[] documentByteArray = outputStream.toByteArray();

            String digestValueBase64 = signedDocument.getDigest(DigestAlgorithm.SHA256).getBase64Value();
            String signedPdfBase64 = Base64.getEncoder().encodeToString(documentByteArray);
            String signatureValueBase64 = Base64.getEncoder().encodeToString(signatureValue.getValue());

            response.setPdfBase64(signedPdfBase64);
            response.setMessageDigestBase64(digestValueBase64);
            response.setSignatureValueBase64(signatureValueBase64);

            return ResponseEntity.ok(response);
        }
        catch (Exception e)
        {
            System.out.println("Exception lancée : " + e);
            Map<String, String> errors = new HashMap<>();
            errors.put("erreur", "un paramètre est incorrect.");
            return ResponseEntity.badRequest().body(errors);
        }
    }

    @PostMapping("/java/signatures/eid/prepare")
    ResponseEntity<?> prepareSignatureWeb_eID(@Valid @RequestBody WebeIDSignaturePreparationRequest signatureParams)
    {
        try
        {
            String pdfBase64 = signatureParams.getSignatureParameters().getPdfBase64();
            byte[] pdfFile = Base64.getDecoder().decode(pdfBase64);

            DSSDocument toSignDocument = new InMemoryDocument(pdfFile);

            CertificateDER certificateDerAsBase64 = new CertificateDER(signatureParams.getCertificateBase64());
            CertificateToken certificateToken = new CertificateToken(certificateDerAsBase64.convertToX509Certificate());
            WebeIDSignaturePreparationResponse signaturePreparationResponse = new WebeIDSignaturePreparationResponse();

            Date signingDate = signatureParams.getSigningDate();
            Digest digest = signService.prepareSignature(toSignDocument, certificateToken, signingDate);
            String digestAlgorithm = SignatureAlgorithmMapper.getDigestAlgorithm(signService.getDefaultDigestAlgorithm());

            signaturePreparationResponse.setHashValue(digest.getBase64Value());
            signaturePreparationResponse.setHashFunction(digestAlgorithm);

            return ResponseEntity.ok(signaturePreparationResponse);
        }
        catch (Exception e)
        {
            System.out.println("Exception lancée : " + e);
            Map<String, String> errors = new HashMap<>();
            errors.put("erreur", "un paramètre est incorrect.");
            return ResponseEntity.badRequest().body(errors);
        }
    }

    @PostMapping("/java/signatures/eid/finalize")
    ResponseEntity<?> finalizeprepareSignatureWeb_eID(@Valid @RequestBody WebeIDSignatureFinalizeRequest signatureParams)
    {
        try
        {
            String pdfBase64 = signatureParams.getSignatureParameters().getPdfBase64();
            byte[] pdfFile = Base64.getDecoder().decode(pdfBase64);

            DSSDocument toSignDocument = new InMemoryDocument(pdfFile);

            SignatureValue signature = new SignatureValue();
            byte[] signatureBytes = Base64.getDecoder().decode(signatureParams.getSignatureBase64());

            SignatureAlgorithmDTO signatureAlgorithmDTO = signatureParams.getSignatureAlgorithmDTO();
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithmMapper.from(signatureAlgorithmDTO.getCryptoAlgorithm(), signatureAlgorithmDTO.getHashFunction());

            signature.setValue(signatureBytes);
            signature.setAlgorithm(signatureAlgorithm);

            CertificateDER certificateDerAsBase64 = new CertificateDER(signatureParams.getCertificateBase64());
            CertificateToken certificateToken = new CertificateToken(certificateDerAsBase64.convertToX509Certificate());
            Date signingDate = signatureParams.getSigningDate();
            String hashValueBase64 = signatureParams.getHashValue();

            var digestValue = Base64.getDecoder().decode(hashValueBase64);
            DigestAlgorithm digestAlgo = SignatureAlgorithmMapper.getDigestAlgorithm(signatureAlgorithmDTO.getHashFunction());
            Digest messageDigest = new Digest(digestAlgo, digestValue);
            DSSDocument signedDocument = signService.finalizeSignature(toSignDocument, signature, certificateToken, signingDate, messageDigest);

            WebeIDSignatureFinalizeResponse signatureResponse = new WebeIDSignatureFinalizeResponse();

            return ResponseEntity.ok(new SignatureFinalizeResponseDTO("Signature Finalized!", true));
        }
        catch (Exception e)
        {
            System.out.println("Exception lancée : " + e);
            Map<String, String> errors = new HashMap<>();
            errors.put("erreur", "un paramètre est incorrect.");
            return ResponseEntity.badRequest().body(errors);
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

            File file = new File("sample.pdf");
            DSSDocument toSignDocument = new FileDocument(file);
            //DSSDocument dssDocument = signService.sign(toSignDocument, Optional.of(fieldParameters));
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }

        return ResponseEntity.ok("PDF Signed!");
    }

    @PostMapping("/signatures/eid/prepare")
    ResponseEntity<SignaturePreparationResponseDTO> prepareSignature(@Valid @RequestBody SignaturePreparationRequestDTO signaturePrepareRequest)
    {
        try
        {
            SignaturePreparationResponseDTO signaturePreparationResponseDTO = new SignaturePreparationResponseDTO();
//            CertificateDER certificateDer = new CertificateDER(signaturePrepareRequest.getCertificateBase64());
//            CertificateToken certificateToken = new CertificateToken(certificateDer.convertToX509Certificate());
//
//            Digest digest = signService.prepareSignature(certificateToken);
//            String digestAlgorithm = SignatureAlgorithmMapper.getDigestAlgorithm(signService.getDefaultDigestAlgorithm());
//
//            signaturePreparationResponseDTO.setHashValue(digest.getBase64Value());
//            signaturePreparationResponseDTO.setHashFunction(digestAlgorithm);

            return ResponseEntity.ok(signaturePreparationResponseDTO);
        }
        catch (Exception e)
        {
            return ResponseEntity.badRequest().body(new SignaturePreparationResponseDTO());
        }
    }

    @GetMapping("read-page")
    ResponseEntity<String> readPage()
    {
        File file = new File("morepage3.pdf");
        DSSDocument document = new FileDocument(file);
        signService.readSignaturePage(document);
        return ResponseEntity.ok("Page read");
    }

    @GetMapping("write-page")
    ResponseEntity<String> writePage()
    {
        File file = new File("sample.pdf");
        DSSDocument document = new FileDocument(file);
        signService.addSignaturePage(document);
        return ResponseEntity.ok("Page write");
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

            //signService.finalizeSignature(signature);

            return ResponseEntity.ok(new SignatureFinalizeResponseDTO("Signature Finalized!", true));
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
            return ResponseEntity.badRequest().body(new SignatureFinalizeResponseDTO("La signature n'a pas été finalisée", false));
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
            File file = new File("sample.pdf");
            DSSDocument toSignDocument = new FileDocument(file);
            //DSSDocument dssDocument = signService.sign(toSignDocument, Optional.of(fieldParameters));

            fieldParameters = new SignatureFieldParameters();
            // the origin is the left and top corner of the page
            fieldParameters.setOriginX(80);
            fieldParameters.setOriginY(10);
            fieldParameters.setWidth(50);
            fieldParameters.setHeight(50);

            //signService.sign(dssDocument, Optional.of(fieldParameters));
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }

        return ResponseEntity.ok("PDF Saved (double signature) !");
    }
}
