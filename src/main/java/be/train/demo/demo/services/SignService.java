package be.train.demo.demo.services;

import be.train.demo.demo.models.CertificatesHolder;
import com.nimbusds.jose.shaded.gson.JsonObject;
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
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.token.*;
import eu.europa.esig.dss.utils.Utils;
import lombok.AllArgsConstructor;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.tsp.TSPUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.MimeType;
import org.springframework.util.ResourceUtils;
import tools.jackson.core.ObjectReadContext;

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
    //private final DSSDocument signatureImage = new InMemoryDocument(getClass().getResourceAsStream("/signature-pen.png"), "signature-pen", MimeTypeEnum.PNG);
    private final PdfBoxSignatureService pdfBoxSignatureService;
    private final static String defaultCert = "self-signed.p12";
    private final static String defaultPass = "changeit";
    private static String FilenameCertificateP12 = defaultCert;
    private static String PasswordCertificateP12 = defaultPass;

    public void PushCertificateForDemo(String cert, String pass)
    {
        FilenameCertificateP12 = cert;
        PasswordCertificateP12 = pass;
    }

    public void PopCertificateForDemo()
    {
        FilenameCertificateP12 = defaultCert;
        PasswordCertificateP12 = defaultPass;
    }

    public void clientSidePadesForRemoteSigning() throws Exception
    {
        File file = new File("sample.pdf");
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

    private CertificatesHolder queryUserCertificates() throws Exception
    {
        //fixme: these are just dummy certificates - replace with real implementation
        CertificatesHolder certificatesHolder = new CertificatesHolder();
        KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(PasswordCertificateP12.toCharArray());
        File p12File = new File(FilenameCertificateP12);
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken(p12File, pp))
        {
            // Set the signing certificate and a certificate chain for the used token
            DSSPrivateKeyEntry privateKey = goodUserToken.getKeys().getFirst();
            certificatesHolder.setCertificate(privateKey.getCertificate());
            certificatesHolder.setCertificateChain(privateKey.getCertificateChain());
        }
        return certificatesHolder;
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
        //signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setReason("La raison est simple xyz");
        signatureParameters.setSignerName("Jean Claude");
        signatureParameters.setLocation("Belgium");
        signatureParameters.setContentSize(15000);

        // Maybe add more bLevel attributes?
        signatureParameters.bLevel().setSigningDate(new Date());

        return signatureParameters;
    }

    public CertificateToken getTokenFromJson(JsonObject jsonObject) throws Exception
    {
        String certBase64 = jsonObject.getAsString();
        byte[] certBytes = Base64.getDecoder().decode(certBase64);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certBytes));

        return new CertificateToken(cert);
    }

    public DSSDocument sign(DSSDocument toSignDocument, Optional<SignatureFieldParameters> fieldParameters) throws Exception
    {
        KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(PasswordCertificateP12.toCharArray());
        File p12File = new File(FilenameCertificateP12);
        System.out.println("Cert: " + FilenameCertificateP12 + " | Pass : " + PasswordCertificateP12);
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken(p12File, pp))
        {
            PAdESSignatureParameters signatureParameters = initParameters();

            // Set the signing certificate and a certificate chain for the used token
            DSSPrivateKeyEntry privateKey = goodUserToken.getKeys().getFirst();
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());

            System.out.println("Bas64: " + Base64.getEncoder().encode(privateKey.getCertificate().getEncoded()));

            // initialize signature field parameters
            // the origin is the left and top corner of the page
            if (fieldParameters.isPresent() && false)
            {
                SignatureImageParameters imageParameters = new SignatureImageParameters();
                //imageParameters.setImage(signatureImage);
                imageParameters.setFieldParameters(fieldParameters.get());
                signatureParameters.setImageParameters(imageParameters);
            }

            //padesService.setTspSource(getTspSource());

            // Only for pades baseline LT (QES only)
            //OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
            //onlineOCSPSource.setDataLoader(new OCSPDataLoader());
            //certificateVerifier.setOcspSource(onlineOCSPSource);

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
        KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(PasswordCertificateP12.toCharArray());
        File p12File = new File(FilenameCertificateP12);
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken(p12File, pp))
        {
            return goodUserToken.signDigest(messageDigest, goodUserToken.getKeys().getFirst());
        }
    }

    /**
     * This method setups the data to sign and returns the digest to sign
     * using the input certificate.
     * Implementation for Web eID
     * */
    public Digest PrepareSignature(CertificateToken certificateToken)
    {
        File file = new File("sample.pdf");
        DSSDocument toSignDocument = new FileDocument(file);

        var params = initParameters();

        params.setSigningCertificate(certificateToken);

        ToBeSigned dataToSign = padesService.getDataToSign(toSignDocument, params);
        byte[] digest = DSSUtils.digest(params.getDigestAlgorithm(), dataToSign.getBytes());
        return new Digest(params.getDigestAlgorithm(), digest);
    }

    /**
     * This method signs the document by inserting the signature value in the CMS
     * that is embedded in the document.
     * Implementation for Web eID
     * */
    public boolean FinalizeSignature(SignatureValue signatureValue, SignatureAlgorithm signatureAlgorithm) throws Exception
    {
        File file = new File("sample.pdf");
        DSSDocument toSignDocument = new FileDocument(file);

        var params = initParameters();

        // Make verifications to ensure the signature value is right

        params.setDigestAlgorithm(signatureAlgorithm.getDigestAlgorithm());
        DSSDocument signedDocument = padesService.signDocument(toSignDocument, params, signatureValue);
        signedDocument.save("remotepdf.pdf");
        return true;
    }
}
