package be.train.demo.demo.services;

import eu.europa.esig.dss.cades.signature.CMSBuilder;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfSignatureCache;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import lombok.AllArgsConstructor;
import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

@Service
@AllArgsConstructor
public class SignService {

    private final PdfBoxSignatureService signatureService;
    private final CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
    private final PAdESService padesService = new PAdESService(certificateVerifier);

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

    public void newSign() throws Exception
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

        DSSMessageDigest messageDigest = signatureService.messageDigest(document, signatureParameters);
        DSSDocument savedDoc = signatureService.sign(document, messageDigest.getValue(), signatureParameters);
        savedDoc.save("savedpdf.pdf");
    }
}


