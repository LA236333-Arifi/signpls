package be.train.demo.demo.enums;

import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import lombok.Getter;

import java.util.List;

public enum CustomCommitmentType implements CommitmentType
{
    ItsmeTestingPurposes("It indicates that the signer does not take any commitment but created the signature for testing purposes only.", "1.3.6.1.4.1.49274.1.2.1");

    /**
     * Object Identifier
     */
    @Getter
    private final String oid;

    /**
     * Description
     */
    @Getter
    private final String description;


    CustomCommitmentType(String description, String oid)
    {
        this.oid = oid;
        this.description = description;
    }

    @Override
    public String[] getDocumentationReferences() {
        return (String[])List.of("https://www.itsme-id.com/hubfs/Legal%20Information%20-%20B2B%20Website/Sign%20Document%20Repository/Test%20Signature%20Policy/compl_pol_testsignaturepolicy-version-1-2.pdf").toArray();
    }

    @Override
    public ObjectIdentifierQualifier getQualifier() {
        return ObjectIdentifierQualifier.OID_AS_URI;
    }

    @Override
    public String getUri() {
        return "https://www.itsme-id.com/hubfs/Legal%20Information%20-%20B2B%20Website/Sign%20Document%20Repository/Test%20Signature%20Policy/compl_pol_testsignaturepolicy-version-1-2.pdf";
    }
}
