package be.train.demo.demo.services;

import be.train.demo.demo.models.CertificatesHolder;
import eu.europa.esig.dss.cades.signature.CMSBuilder;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSSignedDocument;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.signature.SignaturePolicy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
import eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfSignatureCache;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxSignatureService;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.token.*;
import eu.europa.esig.dss.utils.Utils;
import lombok.AllArgsConstructor;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.tsp.TSPUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.MimeType;
import org.springframework.util.ResourceUtils;

import javax.swing.text.Document;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
@AllArgsConstructor
public class SignService
{
    private final CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
    private final PAdESService padesService = new PAdESService(certificateVerifier);
    private final DSSDocument signatureImage = new InMemoryDocument(getClass().getResourceAsStream("/signature-pen.png"), "signature-pen", MimeTypeEnum.PNG);
    private final PdfBoxSignatureService pdfBoxSignatureService;

    public void clientSidePadesForRemoteSigning() throws Exception
    {
        File file = ResourceUtils.getFile("classpath:sample.pdf");
        DSSDocument toSignDocument = new FileDocument(file);

        var params = initParameters();
        padesService.setTspSource(getTspSource());

        CertificatesHolder certificatesHolder = queryUserCertificates();
        if (certificatesHolder.isValid())
        {
            params.setSigningCertificate(certificatesHolder.getCertificate());
            params.setCertificateChain(certificatesHolder.getCertificateChain());
        }

        ToBeSigned dataToSign = padesService.getDataToSign(toSignDocument, params);
        byte[] digest = DSSUtils.digest(params.getDigestAlgorithm(), dataToSign.getBytes());
        DSSMessageDigest messageDigest = new DSSMessageDigest(params.getDigestAlgorithm(), digest);
        SignatureValue remoteSignature = computeSignatureValueRemotely(messageDigest);

        DSSDocument signedDocument = padesService.signDocument(toSignDocument, params, remoteSignature);
        signedDocument.save("remotepdf.pdf");
    }

    private CertificatesHolder queryUserCertificates()
    {
        //fixme: these are just dummy certificates - replace with real implementation
        Certificate[] certs = new Certificate[10];
        return certs;
    }

    public OnlineTSPSource getTspSource()
    {
        String tspServer = "https://freetsa.org/tsr";

        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
        onlineTSPSource.setDataLoader(new TimestampDataLoader());

        return onlineTSPSource;
    }

    private PAdESSignatureParameters initParameters()
    {
        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setAppName("MY SUPER DEMO APP");
        //signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setReason("La raison est simple xyz");
        signatureParameters.setSignerName("Jean Claude");
        signatureParameters.setLocation("Belgium");

        // Maybe add more bLevel attributes?
        signatureParameters.bLevel().setSigningDate(new Date());

        return signatureParameters;
    }

    public String keystore() throws Exception
    {
        File keyStoreFile  = ResourceUtils.getFile("classpath:localhost.p12");

        // instantiate the KeyStore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(Files.newInputStream(keyStoreFile.toPath()), "changeit".toCharArray());

        String cert = keyStore.getCertificate("1").getPublicKey().toString();
        System.out.println(cert);

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
                System.out.println(entry.getClass());
                //System.out.println(entry.getCertificate().getCertificate());
            }


            ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
            SignatureValue signatureValue = goodUserToken.sign(toBeSigned, DigestAlgorithm.SHA256, keys.get(0));

            String buildUp = "CertificateEntryCount :" + loopCounter + " <br>" + "Signature value : " + Utils.toBase64(signatureValue.getValue());
            System.out.println("Signature value : " + Utils.toBase64(signatureValue.getValue()));
            return buildUp;
        }
    }

    public void revoke() throws Exception
    {
        CRLToken crlToken;
        PdfTimestampToken tt;
        //signatureParameters.setContentTimestampParameters(new PAdESTimestampParameters(signatureParameters.getDigestAlgorithm()));
        //TimestampToken timestampToken =  padesService.getContentTimestamp(toSignDocument, signatureParameters);
        //signatureParameters.setContentTimestamps(Arrays.asList(timestampToken));
        //System.out.println(timestampToken);
        //certificateVerifier.setAlertOnMissingRevocationData(null); // Désactive l'alerte
        //toSignDocument = padesService.timestamp(toSignDocument, new PAdESTimestampParameters(signatureParameters.getDigestAlgorithm()));

        // Option 1
        //ExternalCMSService externalCMSService = new ExternalCMSService(certificateVerifier);
        //externalCMSService.signMessageDigest(messageDigest, params, remoteSignature);

        // Option 2
        //CmsService.signDocument(toSignDocument, params, cmsDoc);
    }

    public DSSDocument sign(DSSDocument toSignDocument, Optional<SignatureFieldParameters> fieldParameters) throws Exception
    {
        KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection("changeit".toCharArray());
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken("src/main/resources/self-signed.p12", pp))
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

            padesService.setTspSource(getTspSource());

            // Sign in three steps using the document obtained after the first signature
            ToBeSigned dataToSign = padesService.getDataToSign(toSignDocument, signatureParameters);
            SignatureValue signatureValue = goodUserToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedDocument = padesService.signDocument(toSignDocument, signatureParameters, signatureValue);
            signedDocument.save("signedpdf.pdf");
            return signedDocument;
        }
    }

    private SignatureValue computeSignatureValueRemotely(DSSMessageDigest messageDigest) throws Exception
    {
        //TODO: replace that with the remote integration
        KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection("changeit".toCharArray());
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken("src/main/resources/self-signed.p12", pp))
        {
            return goodUserToken.signDigest(messageDigest, goodUserToken.getKeys().getFirst());
        }
    }
}
