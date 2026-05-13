package be.sbim.controllers;

import be.sbim.common.CertificateDER;
import be.sbim.models.*;
import be.sbim.models.WebeID.*;
import be.sbim.models.pdf.PdfBase64;
import be.sbim.services.SignService;
import be.sbim.utils.SignConstants;
import be.sbim.utils.SignatureAlgorithmMapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;

@RestController()
@RequestMapping("/SignElec/java")
public class SignController
{
    @Autowired
    SignService signService;

    @PostMapping("/signatures/sbim")
    ResponseEntity<?> SignSimpleSbim(@Valid @RequestBody SimpleSignatureRequest signatureParams)
    {
        try
        {
            List<DefautSignatureParameters> listDocuments = signatureParams.getSignatureParameters();
            if (listDocuments.size() > SignConstants.MaxDocumentsToSignInOneBatch)
            {
                return ResponseEntity.status(HttpStatus.CONTENT_TOO_LARGE).build();
            }

            MultipleSignaturesResponse signaturesResponse = new MultipleSignaturesResponse();
            for (DefautSignatureParameters document : listDocuments)
            {
                String pdfBase64 = document.getPdfBase64();
                byte[] pdfFile = Base64.getDecoder().decode(pdfBase64);
                DSSDocument toSignDocument = new InMemoryDocument(pdfFile);

                int page = signService.getSignaturePage(toSignDocument);
                SignerInfo signerInfo = signatureParams.getSignerInfo();
                SignInput signInput = new SignInput(signerInfo.getNom(), signerInfo.getPrenom(), page);
                DigestAlgorithm digestAlgorithm = SignatureAlgorithmMapper.getDigestAlgorithm(signatureParams.getHashFunction());

                SignOutput signOutput = signService.sign(toSignDocument, digestAlgorithm, signInput);

                SimpleSignatureResponse response = MakeSignatureResponseFromSignOutput(signOutput, document.getEtapeId());
                signaturesResponse.getSignatureResponses().add(response);
            }

            return ResponseEntity.ok(signaturesResponse);
        }
        catch (Exception e)
        {
            System.out.println("Exception lancée : " + e);
            Map<String, String> errors = new HashMap<>();
            errors.put("erreur", "un paramètre est incorrect.");
            return ResponseEntity.badRequest().body(errors);
        }
    }

    @PostMapping("/signatures/eid/prepare")
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

            WebeIDSignPrepareOutput prepareOutput = signService.prepareSignature(toSignDocument, certificateToken);

            Digest digest = prepareOutput.getMessageDigest();
            String digestAlgorithm = SignatureAlgorithmMapper.getDigestAlgorithm(prepareOutput.getDigestAlgorithm());

            signaturePreparationResponse.setHashValue(digest.getBase64Value());
            signaturePreparationResponse.setHashFunction(digestAlgorithm);
            signaturePreparationResponse.setSigningDate(prepareOutput.getSigningDate());

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

    @PostMapping("/signatures/eid/finalize")
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
            String hashValueBase64 = signatureParams.getHashValue();

            byte[] digestValue = Base64.getDecoder().decode(hashValueBase64);
            DigestAlgorithm digestAlgo = SignatureAlgorithmMapper.getDigestAlgorithm(signatureAlgorithmDTO.getHashFunction());

            Date signingDate = signatureParams.getSigningDate();
            Digest messageDigest = new Digest(digestAlgo, digestValue);
            SignOutput signOutput = signService.finalizeSignature(toSignDocument, signature, certificateToken, signingDate, messageDigest);

            SimpleSignatureResponse response = MakeSignatureResponseFromSignOutput(signOutput, signatureParams.getSignatureParameters().getEtapeId());
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

    @PostMapping("/pdf/ajouter-page")
    ResponseEntity<?> ajouterPagePdf(@Valid @RequestBody PdfBase64 pdfDocumentBase64)
    {
        try
        {
            String pdfBase64 = pdfDocumentBase64.getPdfBase64();
            byte[] pdfFile = Base64.getDecoder().decode(pdfBase64);
            DSSDocument pdfDocument = new InMemoryDocument(pdfFile);

            DSSDocument pagedDoc = signService.addSignaturePage(pdfDocument);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            pagedDoc.writeTo(outputStream);
            byte[] documentByteArray = outputStream.toByteArray();

            String pagedPdfBase64 = Base64.getEncoder().encodeToString(documentByteArray);
            PdfBase64 pagedDocument = new PdfBase64(pagedPdfBase64);
            return ResponseEntity.ok(pagedDocument);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    private SimpleSignatureResponse MakeSignatureResponseFromSignOutput(SignOutput signOutput, Long etapeId)
    {
        SimpleSignatureResponse response = new SimpleSignatureResponse();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        DSSDocument signedDocument = signOutput.getSignedDocument();
        SignatureValue signatureValue = signOutput.getSignatureValue();

        try
        {
            signedDocument.writeTo(outputStream);
            byte[] documentByteArray = outputStream.toByteArray();

            String digestValueBase64 = signedDocument.getDigest(signOutput.getDigestAlgorithm()).getBase64Value();
            String signedPdfBase64 = Base64.getEncoder().encodeToString(documentByteArray);
            String signatureValueBase64 = Base64.getEncoder().encodeToString(signatureValue.getValue());

            response.setMessageDigestBase64(digestValueBase64);
            response.setPdfBase64(signedPdfBase64);
            response.setSignatureValueBase64(signatureValueBase64);
            response.setEtapeId(etapeId);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }

        return response;
    }
}
