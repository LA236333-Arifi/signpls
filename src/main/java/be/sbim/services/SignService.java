package be.sbim.services;

import be.sbim.models.SignInput;
import be.sbim.models.SignOutput;
import be.sbim.models.WebeID.WebeIDSignPrepareOutput;
import be.sbim.utils.SignConstants;
import be.sbim.utils.SignatureAlgorithmMapper;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.*;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDocumentReader;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxSignatureService;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.signature.SignatureValueChecker;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.*;
import lombok.AllArgsConstructor;
import org.apache.pdfbox.pdmodel.*;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.*;
import java.util.*;

@Service
@AllArgsConstructor
public class SignService
{
    private final CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
    private final PAdESService padesService = new PAdESService(certificateVerifier);
    private final PdfBoxSignatureService pdfBoxSignatureService;
    private final static String defaultCert = "self-signed.p12";
    private final static String defaultPass = "changeit";
    private final static DSSFont font = new DSSFileFont(Objects.requireNonNull(SignService.class.getResourceAsStream
            ("/fonts/signature-regular.ttf")));

    public OnlineTSPSource getTsaSource()
    {
        // Serveur gratuit pour avoir un timestamp token mais avec un gros rate limiting (faible débit)
        String tspServer = "https://freetsa.org/tsr";

        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
        onlineTSPSource.setDataLoader(new TimestampDataLoader());

        return onlineTSPSource;
    }

    public SignatureLevel getDefaultSignatureLevel()
    {
        return SignConstants.DefaultSignatureLevel;
    }

    public DigestAlgorithm getDefaultDigestAlgorithm()
    {
        return SignatureAlgorithmMapper.getDigestAlgorithm(SignConstants.SHA_256);
    }

    private PAdESSignatureParameters initParameters()
    {
        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setAppName(SignConstants.AppName);
        signatureParameters.setSignatureLevel(getDefaultSignatureLevel());
        signatureParameters.setDigestAlgorithm(getDefaultDigestAlgorithm());
        signatureParameters.setReason("Signature Document SignElec");
        signatureParameters.setContentSize(15000);

        return signatureParameters;
    }

    public DSSDocument addSignaturePage(DSSDocument dssDocument)
    {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (PdfBoxDocumentReader reader = new PdfBoxDocumentReader(dssDocument))
        {
            PDDocument document = reader.getPDDocument();
            PDPage page = new PDPage();
            document.addPage(page);
            document.save(outputStream);
            DSSDocument pagedDocument = new InMemoryDocument(outputStream.toByteArray());
            return pagedDocument;
        }
        catch (IOException exception)
        {
            System.out.println(exception.getMessage());
            throw new RuntimeException();
        }
    }

    public int getSignaturePage(DSSDocument dssDocument)
    {
        try (PdfBoxDocumentReader reader = new PdfBoxDocumentReader(dssDocument))
        {
            PDDocument document = reader.getPDDocument();
            return document.getNumberOfPages();
        }
        catch (IOException exception)
        {
            System.out.println(exception.getMessage());
            throw new RuntimeException();
        }
    }

    public PAdESSignatureParameters getVisualSignatureParameters(String nom, String prenom, int signaturePosition, int pageNumber)
    {
        PAdESSignatureParameters signatureParameters = initParameters();
        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setFieldParameters(fieldParameters);
        imageParameters.setTextParameters(textParameters);
        signatureParameters.setImageParameters(imageParameters);

        int idx = signaturePosition - 1;
        if (idx < 0 || idx >= SignConstants.SignaturesPerPage)
        {
            throw new IllegalArgumentException("signaturePosition doit être entre 1 et "
                    + SignConstants.SignaturesPerPage);
        }
        int col = idx % SignConstants.GridCols;
        int row = idx / SignConstants.GridCols;

        float usableW = SignConstants.PageWidth  - 2 * SignConstants.PageMargin;
        float usableH = SignConstants.PageHeight - 2 * SignConstants.PageMargin;
        float cellW   = usableW / SignConstants.GridCols;
        float cellH   = usableH / SignConstants.GridRows;

        float originX = SignConstants.PageMargin + col * cellW + SignConstants.CellPadding / 2f;
        float originY = SignConstants.PageMargin + row * cellH + SignConstants.CellPadding / 2f;
        float width   = cellW - SignConstants.CellPadding;
        float height  = cellH - SignConstants.CellPadding;

        fieldParameters.setOriginX(originX);
        fieldParameters.setOriginY(originY);
        fieldParameters.setWidth(width);
        fieldParameters.setHeight(height);
        fieldParameters.setPage(pageNumber); // 1-indexed

        String nomAvecInitialeMaj = nom.substring(0, 1).toUpperCase() + nom.substring(1);
        String prenomAvecInitialeMaj = prenom.substring(0, 1).toUpperCase() + prenom.substring(1);
        String signerName = nomAvecInitialeMaj + prenomAvecInitialeMaj;
        signatureParameters.setSignerName(signerName);
        textParameters.setText(signerName);
        textParameters.setFont(font);
        textParameters.setPadding(20);
        return signatureParameters;
    }

    public SignOutput sign(DSSDocument toSignDocument, DigestAlgorithm digestAlgorithm, SignInput signInput) throws Exception
    {
        KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(defaultPass.toCharArray());
        File p12File = new File(defaultCert);
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken(p12File, pp))
        {
            PAdESSignatureParameters signatureParameters = getVisualSignatureParameters(signInput.getNom(), signInput.getPrenom(), signInput.getSignaturePosition(), signInput.getPage());
            signatureParameters.setDigestAlgorithm(digestAlgorithm);

            // Set the signing certificate and a certificate chain for the used token
            DSSPrivateKeyEntry privateKey = goodUserToken.getKeys().getFirst();
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());

            //padesService.setTspSource(getTsaSource());

            // Sign in three steps using the document obtained after the first signature
            ToBeSigned dataToSign = padesService.getDataToSign(toSignDocument, signatureParameters);
            SignatureValue signatureValue = goodUserToken.sign(dataToSign, signatureParameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedDocument = padesService.signDocument(toSignDocument, signatureParameters, signatureValue);

            SignOutput output = new SignOutput(signatureValue, signedDocument, signatureParameters.getDigestAlgorithm());
            return output;
        }
    }

    /**
     * This method setups the data to sign and returns the digest to sign
     * using the input certificate.
     * Implementation for Web eID
     * */
    public WebeIDSignPrepareOutput prepareSignature(DSSDocument toSignDocument, CertificateToken certificateToken) throws Exception
    {
        PAdESSignatureParameters params = initParameters();
        params.setSigningCertificate(certificateToken);

        ToBeSigned dataToSign = padesService.getDataToSign(toSignDocument, params);

        byte[] digest = DSSUtils.digest(params.getDigestAlgorithm(), dataToSign.getBytes());
        Digest messageDigest = new Digest(params.getDigestAlgorithm(), digest);

        return new WebeIDSignPrepareOutput(messageDigest, params.getSigningDate(), params.getDigestAlgorithm());
    }

    /**
     * This method signs the document by inserting the signature value in the CMS
     * that is embedded in the document.
     * Implementation for Web eID
     * */
    public SignOutput finalizeSignature(DSSDocument toSignDocument, SignatureValue signatureValue, CertificateToken certificateToken, Date signingDate, Digest messageDigest) throws Exception
    {
        var params = initParameters();
        params.setSigningCertificate(certificateToken);
        params.bLevel().setSigningDate(signingDate);

        SignatureAlgorithm signatureAlgorithm = params.getSignatureAlgorithm();
        if (!validateSignature(messageDigest, signatureValue, certificateToken, signatureAlgorithm))
        {
            throw new SignatureException("Signature value is wrong");
        }

        DSSDocument signedDocument = padesService.signDocument(toSignDocument, params, signatureValue);
        SignOutput output = new SignOutput(signatureValue, signedDocument, params.getDigestAlgorithm());
        return output;
    }


    public boolean validateSignature(Digest digest, SignatureValue givenSignature, CertificateToken signingCertificate, SignatureAlgorithm expectedSignatureAlgorithm)
    {
        // La SignatureValue a été signée par la clée privée, il faut au moins vérifier la
        // signature avec la clé publique correspondante. D'autres vérifications post-signature
        // pourraient avoir lieu pour vérifier les certificats, etc.
        try
        {
            SignatureValue signatureValue = new SignatureValue();
            signatureValue.setValue(givenSignature.getValue());
            signatureValue.setAlgorithm(givenSignature.getAlgorithm());

            SignatureValueChecker signatureValueChecker = new SignatureValueChecker();
            signatureValue = signatureValueChecker.ensureSignatureValue(signatureValue, expectedSignatureAlgorithm);

            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithmMapper.from(signatureValue.getAlgorithm().getEncryptionAlgorithm(), null);
            signatureValue.setAlgorithm(signatureAlgorithm);

            Signature signature = Signature.getInstance(signatureValue.getAlgorithm().getJCEId(), DSSSecurityProvider.getSecurityProviderName());
            System.out.println("Signature Algorithm: " + signatureValue.getAlgorithm().getJCEId());
            System.out.println("Public Key infomration: " + signingCertificate.getPublicKey());
            signature.initVerify(signingCertificate.getPublicKey());
            signature.update(digest.getValue());
            boolean debugVerify = signature.verify(signatureValue.getValue());
            System.out.println("signature.verifiy value: " + debugVerify);
            return debugVerify;
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
            return false;
        }
    }
}
