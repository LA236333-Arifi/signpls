package be.train.demo.demo.services;

import be.train.demo.demo.models.SignOutput;
import be.train.demo.demo.models.WebeID.WebeIDSignPrepareOutput;
import be.train.demo.demo.utils.SignatureAlgorithmMapper;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.*;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.PdfSignatureCache;
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
import org.apache.pdfbox.pdmodel.interactive.documentnavigation.destination.*;
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
    //private final static DSSDocument signatureImage = new InMemoryDocument(getClass().getResourceAsStream("/signature-pen.png"), "signature-pen", MimeTypeEnum.PNG);
    private final PdfBoxSignatureService pdfBoxSignatureService;
    private final static String defaultCert = "self-signed.p12";
    private final static String defaultPass = "changeit";
    private static CertificateToken currentCertificate;
    private static PdfSignatureCache currentSignatureCache;
    private static Date currentDate;
    private static Digest currentMessageDigest;

    public OnlineTSPSource getTsaSource()
    {
        String tspServer = "https://freetsa.org/tsr";

        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
        onlineTSPSource.setDataLoader(new TimestampDataLoader());

        return onlineTSPSource;
    }

    public SignatureLevel getDefaultSignatureLevel()
    {
        //return SignatureLevel.PAdES_BASELINE_T;
        return SignatureLevel.PAdES_BASELINE_B;
    }

    public DigestAlgorithm getDefaultDigestAlgorithm()
    {
        return DigestAlgorithm.SHA256;
    }

    private PAdESSignatureParameters initParameters()
    {
        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setAppName("SignElec");
        signatureParameters.setSignatureLevel(getDefaultSignatureLevel());
        signatureParameters.setDigestAlgorithm(getDefaultDigestAlgorithm());
        signatureParameters.setReason("Signature du document SignElec");
        //signatureParameters.setSignerName("Jean Claude");
        signatureParameters.setLocation("Belgium");
        signatureParameters.setContentSize(15000);

        // Add those additional bLevel parameters for Itsme
        //signatureParameters.bLevel().setSignaturePolicy();
        //signatureParameters.bLevel().setCommitmentTypeIndications();
        return signatureParameters;
    }

    private void addSignaturePolicy()
    {
        var params = initParameters();

        List<CommitmentType> commitmentTypeIndications = new ArrayList<>();
        //commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfOrigin);
        commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfApproval);
        Policy policy = new Policy();
        policy.setId("1.3.6.1.4.1.49274.1.1.7.2.0");
        policy.setDescription("COMPL_POL_GenericQualfiedSignatureCreationPolicy");
        policy.setDocumentationReferences("https://testing.itsme-id.com/hubfs/Legal%20Information%20-%20B2B%20Website/Sign%20Document%20Repository/Generic%20Qualified%20Signature%20Policy/compl_pol_genericqualifiedsignaturepolicy-2-0.pdf");

        UserNotice userNotice = new UserNotice();
        userNotice.setOrganization("MyOrganization");
        userNotice.setExplicitText("This is the demo explicit text from MyOrganization");
        userNotice.setNoticeNumbers(1);
        policy.setQualifier(ObjectIdentifierQualifier.OID_AS_URI);
        policy.setUserNotice(userNotice);

        params.bLevel().setSignaturePolicy(policy);
        params.bLevel().setCommitmentTypeIndications(commitmentTypeIndications);
        params.bLevel().setClaimedSignerRoles(List.of("Signataire"));
    }

    public void readSignaturePage(DSSDocument dssDocument)
    {
        try (PdfBoxDocumentReader reader = new PdfBoxDocumentReader(dssDocument))
        {
            PDDocument document = reader.getPDDocument();
            PDDocumentCatalog catalog = document.getDocumentCatalog();

            PDDestination destination = catalog.findNamedDestinationPage(new PDNamedDestination("SpecialSignaturePage"));
            System.out.println("Is destination found : " + (destination != null));

            PDPageFitDestination fitDestination = (PDPageFitDestination) destination;
            System.out.println("Is page pointed by the FitDestination valid : " + (fitDestination.getPage() != null) + " | Page Number (should be 2) : " + (fitDestination.retrievePageNumber() + 1));

            int PageNumber = fitDestination.retrievePageNumber() + 1;

            SignatureFieldParameters parameters = new SignatureFieldParameters();
            parameters.setPage(PageNumber);
            parameters.setOriginY(50);
            parameters.setOriginX(50);
            parameters.setHeight(50);
            parameters.setWidth(50);
            //parameters.setFieldId(UUID.randomUUID().toString());
            //DSSDocument ne = padesService.addNewSignatureField(dssDocument, parameters);
            //ne.save("signatureField.pdf");
        }
        catch (IOException exception)
        {
            System.out.println(exception.getMessage());
        }
    }

    public void addSignaturePage(DSSDocument dssDocument)
    {
        try (PdfBoxDocumentReader reader = new PdfBoxDocumentReader(dssDocument))
        {
            PDDocument document = reader.getPDDocument();
            PDDocumentCatalog catalog = document.getDocumentCatalog();
            PDDestination destination = catalog.findNamedDestinationPage(new PDNamedDestination("SpecialSignaturePage"));
            if (destination == null)
            {
                // Crée la nouvelle page
                PDPage page = new PDPage();
                document.addPage(page);

                // Crée le marqueur de destination et le pointe vers la nouvelle page
                PDPageFitDestination fitDestination = new PDPageFitDestination();
                fitDestination.setPage(page);

                // Crée un dictionnaire de Names au besoin
                PDDocumentNameDictionary nameDictionary = catalog.getNames();
                if (nameDictionary == null)
                {
                    nameDictionary = new PDDocumentNameDictionary(catalog);
                    catalog.setNames(nameDictionary);
                }

                // Récupère le noeud des destinations et le crée au besoin
                PDDestinationNameTreeNode nameTreeNode = nameDictionary.getDests();
                if (nameTreeNode == null)
                {
                    nameTreeNode = new PDDestinationNameTreeNode();
                    nameDictionary.setDests(nameTreeNode);
                }

                Map<String, PDPageDestination> destNames = nameTreeNode.getNames();
                if (destNames == null)
                {
                    // On crée le dictionnaire des Names
                    destNames = new HashMap<>();
                }

                // On ajoute notre marqueur spécial qui pointe vers la page dans le dictionnaire
                destNames.put("SpecialSignaturePage", fitDestination);
                nameTreeNode.setNames(destNames);

                document.save("morepage3.pdf");
            }
            else
            {
                System.out.println("Destination found !");
            }
        }
        catch (IOException exception)
        {
            System.out.println(exception.getMessage());
        }
    }

    public SignOutput sign(DSSDocument toSignDocument, Optional<SignatureFieldParameters> fieldParameters) throws Exception
    {
        KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(defaultPass.toCharArray());
        File p12File = new File(defaultCert);
        try (SignatureTokenConnection goodUserToken = new Pkcs12SignatureToken(p12File, pp))
        {
            PAdESSignatureParameters signatureParameters = initParameters();

            // Set the signing certificate and a certificate chain for the used token
            DSSPrivateKeyEntry privateKey = goodUserToken.getKeys().getFirst();
            signatureParameters.setSigningCertificate(privateKey.getCertificate());
            signatureParameters.setCertificateChain(privateKey.getCertificateChain());

            // initialize signature field parameters
            // the origin is the left and top corner of the page
            if (fieldParameters.isPresent() && false)
            {
                SignatureImageParameters imageParameters = new SignatureImageParameters();
                //imageParameters.setImage(signatureImage);
                imageParameters.setFieldParameters(fieldParameters.get());
                signatureParameters.setImageParameters(imageParameters);
            }

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
