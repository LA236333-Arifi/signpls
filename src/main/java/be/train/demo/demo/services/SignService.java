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

import javax.swing.text.Document;
import java.io.*;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
@AllArgsConstructor
public class SignService
{
    private final CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
    private final PAdESService padesService = new PAdESService(certificateVerifier);
    private final InMemoryDocument signatureImage = new InMemoryDocument(getClass().getResourceAsStream("/signature-pen.png"));

    public void test()
    {
        PAdESWithExternalCMSService CmsService;
        //CmsService.isValidCMSSignedData();
    }

    public List<String> querySomeData() throws Exception
    {
        File file = ResourceUtils.getFile("penpdf.pdf");
        DSSDocument document = new FileDocument(file);

        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-pen.png")));
        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        imageParameters.setFieldParameters(fieldParameters);
        fieldParameters.setOriginX(200);
        fieldParameters.setOriginY(400);
        fieldParameters.setWidth(300);
        fieldParameters.setHeight(200);

        DSSDocument newDoc = padesService.addNewSignatureField(document, fieldParameters);

        return padesService.getAvailableSignatureFields(document);
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

        String haha = keyStore.getCertificate("1").getPublicKey().toString();
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

    public void pen() throws Exception
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
            signatureParameters.setImageParameters(imageParameters);

            // Sign in three steps using the document obtained after the first signature
            ToBeSigned dataToSign = padesService.getDataToSign(toSignDocument, signatureParameters);

            System.out.println("Post getDataToSign: " + padesService.getAvailableSignatureFields(toSignDocument));

            SignatureValue signatureValue = goodUserToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);

            System.out.println("Post goodUserToken.sign: " + padesService.getAvailableSignatureFields(toSignDocument));

            DSSDocument doubleSignedDocument = padesService.signDocument(toSignDocument, signatureParameters, signatureValue);

            System.out.println("Post SignDocument: " + padesService.getAvailableSignatureFields(toSignDocument));

            doubleSignedDocument.save("penpdf.pdf");
        }
    }

    public DSSDocument sign(DSSDocument toSignDocument, Optional<SignatureFieldParameters> fieldParameters) throws Exception
    {
        KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection("changeit".toCharArray());
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken("src/main/resources/localhost.p12", pp))
        {
            PAdESSignatureParameters signatureParameters = initParameters();

            // Set the signing certificate and a certificate chain for the used token
            DSSPrivateKeyEntry privateKey = goodUserToken.getKeys().getFirst();
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());

            // initialize signature field parameters
            // the origin is the left and top corner of the page
            if (fieldParameters.isPresent())
            {
                SignatureImageParameters imageParameters = new SignatureImageParameters();
                imageParameters.setImage(signatureImage);
                imageParameters.setFieldParameters(fieldParameters.get());
                signatureParameters.setImageParameters(imageParameters);
            }

            // Sign in three steps using the document obtained after the first signature
            ToBeSigned dataToSign = padesService.getDataToSign(toSignDocument, signatureParameters);
            SignatureValue signatureValue = goodUserToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedDocument = padesService.signDocument(toSignDocument, signatureParameters, signatureValue);
            signedDocument.save("penpdf.pdf");
            return signedDocument;
        }
    }

    public void doublepen() throws Exception
    {
        //File keyStoreFile = ResourceUtils.getFile("classpath:localhost.p12");
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
            //signatureParameters.setImageParameters(imageParameters);

            // Sign in three steps using the document obtained after the first signature
            ToBeSigned dataToSign = padesService.getDataToSign(toSignDocument, signatureParameters);

            System.out.println("Post getDataToSign: " + padesService.getAvailableSignatureFields(toSignDocument));

            SignatureValue signatureValue = goodUserToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);

            System.out.println("Post goodUserToken.sign: " + padesService.getAvailableSignatureFields(toSignDocument));

            DSSDocument doubleSignedDocument = padesService.signDocument(toSignDocument, signatureParameters, signatureValue);

            System.out.println("Post SignDocument: " + padesService.getAvailableSignatureFields(toSignDocument));

            doubleSignedDocument.save("penpdf.pdf");
            toSignDocument = doubleSignedDocument;
        }

        // Try with toSignDocument before it gets
        File newfile = ResourceUtils.getFile("penpdf.pdf");
        DSSDocument dodoc = toSignDocument;//new FileDocument(newfile);

        pp = new KeyStore.PasswordProtection("changeit".toCharArray());
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken("src/main/resources/localhost.p12", pp))
        {
            PAdESSignatureParameters signatureParameters = initParameters();

            // Set the signing certificate and a certificate chain for the used token
            DSSPrivateKeyEntry privateKey = goodUserToken.getKeys().getFirst();
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());

            SignatureImageParameters imageParameters = new SignatureImageParameters();
            // set an image
            imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-pen.png")));

            // initialize signature field parameters
            SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
            imageParameters.setFieldParameters(fieldParameters);
            // the origin is the left and top corner of the page
            fieldParameters.setOriginX(400);
            fieldParameters.setOriginY(200);
            fieldParameters.setWidth(100);
            fieldParameters.setHeight(100);
            //signatureParameters.setImageParameters(imageParameters);

            // Sign in three steps using the document obtained after the first signature
            ToBeSigned dataToSign = padesService.getDataToSign(dodoc, signatureParameters);

            System.out.println("Post getDataToSign: " + padesService.getAvailableSignatureFields(dodoc));

            SignatureValue signatureValue = goodUserToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);

            System.out.println("Post goodUserToken.sign: " + padesService.getAvailableSignatureFields(dodoc));

            DSSDocument doubleSignedDocument = padesService.signDocument(dodoc, signatureParameters, signatureValue);

            System.out.println("Post SignDocument: " + padesService.getAvailableSignatureFields(dodoc));

            doubleSignedDocument.save("doublepenpdf.pdf");
            toSignDocument = doubleSignedDocument;
        }

        dodoc = toSignDocument;//new FileDocument(newfile);

        pp = new KeyStore.PasswordProtection("changeit".toCharArray());
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken("src/main/resources/localhost.p12", pp))
        {
            PAdESSignatureParameters signatureParameters = initParameters();

            // Set the signing certificate and a certificate chain for the used token
            DSSPrivateKeyEntry privateKey = goodUserToken.getKeys().getFirst();
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());

            SignatureImageParameters imageParameters = new SignatureImageParameters();
            // set an image
            imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-pen.png")));

            // initialize signature field parameters
            SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
            imageParameters.setFieldParameters(fieldParameters);
            // the origin is the left and top corner of the page
            fieldParameters.setOriginX(10);
            fieldParameters.setOriginY(10);
            fieldParameters.setWidth(10);
            fieldParameters.setHeight(10);
            //signatureParameters.setImageParameters(imageParameters);

            // Sign in three steps using the document obtained after the first signature
            ToBeSigned dataToSign = padesService.getDataToSign(dodoc, signatureParameters);

            System.out.println("Post getDataToSign: " + padesService.getAvailableSignatureFields(dodoc));

            SignatureValue signatureValue = goodUserToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);

            System.out.println("Post goodUserToken.sign: " + padesService.getAvailableSignatureFields(dodoc));

            DSSDocument doubleSignedDocument = padesService.signDocument(dodoc, signatureParameters, signatureValue);

            System.out.println("Post SignDocument: " + padesService.getAvailableSignatureFields(dodoc));

            doubleSignedDocument.save("doublepenpdf.pdf");
        }
    }

    public DSSDocument signExternal(DSSDocument toSignDocument, Optional<SignatureFieldParameters> fieldParameters) throws Exception
    {
        KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection("changeit".toCharArray());
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken("src/main/resources/localhost.p12", pp))
        {
            PAdESSignatureParameters signatureParameters = initParameters();

            // Set the signing certificate and a certificate chain for the used token
            DSSPrivateKeyEntry privateKey = goodUserToken.getKeys().getFirst();
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());

            // initialize signature field parameters
            // the origin is the left and top corner of the page
            if (fieldParameters.isPresent())
            {
                SignatureImageParameters imageParameters = new SignatureImageParameters();
                imageParameters.setImage(signatureImage);
                imageParameters.setFieldParameters(fieldParameters.get());
                signatureParameters.setImageParameters(imageParameters);
            }

            signatureParameters.bLevel().setSigningDate(new Date());

            ExternalCMSService padesCMSGeneratorService = new ExternalCMSService(certificateVerifier);

            // 1. Generate DTBS for PAdES
            ToBeSigned dataToSign = padesService.getDataToSign(toSignDocument, signatureParameters);

            // Do we have to send the whole data or the hash ?
            //byte[] gg = DSSUtils.digest(DigestAlgorithm.SHA256, dataToSign.getBytes());


            // 2. Send DTBS to itsme and get signature value
            SignatureValue signatureValue = computeSignatureValueRemotely(
                    dataToSign,
                    signatureParameters.getDigestAlgorithm()
            );

            DSSDocument signedDocument = padesService.signDocument(toSignDocument, signatureParameters, signatureValue);
            signedDocument.save("penpdf.pdf");
            return signedDocument;
        }
    }

    private SignatureValue computeSignatureValueRemotely(ToBeSigned dataToSign, DigestAlgorithm digestAlgorithm)
    {
        return new SignatureValue();
    }
}


