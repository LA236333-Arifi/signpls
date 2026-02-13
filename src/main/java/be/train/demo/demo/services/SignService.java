package be.train.demo.demo.services;

import eu.europa.esig.dss.cades.signature.CMSBuilder;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfSignatureCache;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.*;
import eu.europa.esig.dss.utils.Utils;
import lombok.AllArgsConstructor;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

import java.io.*;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.hibernate.validator.internal.util.Contracts.assertTrue;

@Service
@AllArgsConstructor
public class SignService {

    private final PdfBoxSignatureService signatureService;
    private final CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
    private final PAdESService padesService = new PAdESService(certificateVerifier);

    @Deprecated
    public void pleaseSign() throws Exception
    {
        File file = ResourceUtils.getFile("classpath:sample.pdf");
        DSSDocument document = new FileDocument(file);

        File cert = ResourceUtils.getFile("classpath:localhost.pem");
        CertificateToken certificateToken = DSSUtils.loadCertificate(cert);

        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setAppName("MY SUPER DEMO APP");
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(certificateToken);

        ToBeSigned tbs = padesService.getDataToSign(document, signatureParameters);

        SignatureValue sv = new SignatureValue();
        sv.setAlgorithm(SignatureAlgorithm.RSA_SHA256);
        sv.setValue(tbs.getBytes());

        DSSDocument savedDoc = padesService.signDocument(document, signatureParameters, sv);
        savedDoc.save("pleasepdf.pdf");
    }

    public void test()
    {
        PAdESWithExternalCMSService CmsService;
        //CmsService.isValidCMSSignedData();
    }

    public List<String> querySomeData() throws Exception
    {
        File file = ResourceUtils.getFile("savedpdf.pdf");
        DSSDocument document = new FileDocument(file);

        return signatureService.getAvailableSignatureFields(document);
    }

    private PAdESSignatureParameters initParameters()
    {
        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setAppName("MY SUPER DEMO APP");
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setReason("La raison est simple xyz");
        signatureParameters.setSignerName("Jean Claude");

        return signatureParameters;
    }

    public String keystore() throws Exception
    {
        File keyStoreFile  = ResourceUtils.getFile("classpath:localhost.p12");

        // instantiate the KeyStore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(Files.newInputStream(keyStoreFile.toPath()), "changeit".toCharArray());

        String haha = keyStore.getCertificate("2").getPublicKey().toString();
        System.out.println(haha);

        return keyStore.getProvider().toString();
    }

    public String cook()  throws Exception
    {
        File keyStoreFile  = ResourceUtils.getFile("classpath:localhost.p12");
        KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection("changeit".toCharArray());
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken("src/main/resources/localhost.p12", pp))
        {
            int loopCounter = 0;
            List<DSSPrivateKeyEntry> keys = goodUserToken.getKeys();
            for (DSSPrivateKeyEntry entry : keys) {
                loopCounter++;
                System.out.println(entry.getCertificate().getCertificate());
            }


            ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
            SignatureValue signatureValue = goodUserToken.sign(toBeSigned, DigestAlgorithm.SHA256, keys.get(0));

            String buildUp = "CertificateEntryCount :" + loopCounter + " <br>" + "Signature value : " + Utils.toBase64(signatureValue.getValue());
            System.out.println("Signature value : " + Utils.toBase64(signatureValue.getValue()));
            return buildUp;
        }
    }

    public void dbl() throws Exception
    {
        // We can call KeyStore.Load() with the File parameter
        //File keyStoreFile  = ResourceUtils.getFile("classpath:localhost.p12");
        File file = ResourceUtils.getFile("classpath:sample.pdf");
        DSSDocument toSignDocument = new FileDocument(file);

        KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection("changeit".toCharArray());
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken("src/main/resources/localhost.p12", pp))
        {
            PAdESSignatureParameters signatureParameters = initParameters();

            // Set the signing certificate and a certificate chain for the used token
            DSSPrivateKeyEntry privateKey = goodUserToken.getKeys().getFirst();
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());

            // Sign in three steps using the document obtained after the first signature
            ToBeSigned dataToSign = padesService.getDataToSign(toSignDocument, signatureParameters);
            SignatureValue signatureValue = goodUserToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);

            System.out.println(signatureValue.toString());

            DSSDocument doubleSignedDocument = padesService.signDocument(toSignDocument, signatureParameters, signatureValue);

            doubleSignedDocument.save("lalapdf.pdf");
        }

        File fileDouble = ResourceUtils.getFile("lalapdf.pdf");
        DSSDocument doubleSignatureDocument = new FileDocument(fileDouble);

        KeyStore.PasswordProtection newPP = new KeyStore.PasswordProtection("changeit".toCharArray());
        try (SignatureTokenConnection secondToken = new Pkcs12SignatureToken("src/main/resources/localhost.p12", newPP))
        {
            PAdESSignatureParameters signatureParameters = initParameters();

            // Set the signing certificate and a certificate chain for the used token
            DSSPrivateKeyEntry privateKey = secondToken.getKeys().getFirst();
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());

            // Sign in three steps using the document obtained after the first signature
            ToBeSigned dataToSign = padesService.getDataToSign(toSignDocument, signatureParameters);
            SignatureValue signatureValue = secondToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);

            System.out.println(signatureValue.toString());

            DSSDocument doubleSignedDocument = padesService.signDocument(toSignDocument, signatureParameters, signatureValue);

            doubleSignedDocument.save("lalapdf2.pdf");
        }
    }

    public void wow() throws Exception
    {
        File keyStoreFile  = ResourceUtils.getFile("classpath:localhost.p12");
        File file = ResourceUtils.getFile("classpath:sample.pdf");
        DSSDocument toSignDocument = new FileDocument(file);

        KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection("changeit".toCharArray());
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken("src/main/resources/localhost.p12", pp))
        {
            PAdESSignatureParameters signatureParameters = initParameters();

            // Set the signing certificate and a certificate chain for the used token
            DSSPrivateKeyEntry privateKey = goodUserToken.getKeys().getFirst();
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());

            // Sign in three steps using the document obtained after the first signature
            ToBeSigned dataToSign = padesService.getDataToSign(toSignDocument, signatureParameters);
            SignatureValue signatureValue = goodUserToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);
            DSSDocument doubleSignedDocument = padesService.signDocument(toSignDocument, signatureParameters, signatureValue);
            doubleSignedDocument.save("lalapdf.pdf");
        }

        /*
        // Preparing parameters for the PAdES signature
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setSigningCertificate(privateKey.getCertificate());
        parameters.setCertificateChain(privateKey.getCertificateChain());

        KeyStore ks;

        // Initialize visual signature and configure
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        // set an image
        imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-pen.png")));

        // initialize signature field parameters
        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        imageParameters.setFieldParameters(fieldParameters);
        // the origin is the left and top corner of the page
        fieldParameters.setOriginX(200);
        fieldParameters.setOriginY(400);
        fieldParameters.setWidth(300);
        fieldParameters.setHeight(200);
        parameters.setImageParameters(imageParameters);

        // Create common certificate verifier
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        // Create PAdESService for signature
        PAdESService service = new PAdESService(commonCertificateVerifier);
        service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
        // Get the SignedInfo segment that need to be signed.
        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

        // This function obtains the signature value for signed information using the
        // private key and specified algorithm
        DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
        SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

        // We invoke the xadesService to sign the document with the signature value obtained in
        // the previous step.
        DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
        */
    }

    public void signExternalCMS()
    {
        /*
        ExternalCMSService padesCMSGeneratorService = new ExternalCMSService(certificateVerifier);

        // Configure signature parameters
        // NOTE: parameters concern only CMS signature creation, but the signature level shall correspond
        // to the target level of a PAdES signature
        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        DSSMessageDigest messageDigest = new DSSMessageDigest(); // needs this input

        // Create DTBS (data to be signed) using the message-digest of a PDF signature byte range obtained from a client
        ToBeSigned dataToSign = padesCMSGeneratorService.getDataToSign(messageDigest, signatureParameters);

        // Sign the DTBS using a private key connection or remote-signing service
        SignatureValue signatureValue = computeSignatureValue(dataToSign, signatureParameters.getDigestAlgorithm());

        // Create a CMS signature using the provided message-digest, signature parameters and the signature value
        DSSDocument cmsSignature = padesCMSGeneratorService.signMessageDigest(messageDigest, signatureParameters, signatureValue);
        */
    }
}


