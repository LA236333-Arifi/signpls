package be.train.demo.demo.utils;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

public class SignatureAlgorithmMapper
{
    public static SignatureAlgorithm from(EncryptionAlgorithm encryptionAlgorithm, DigestAlgorithm digestAlgorithm)
    {
        for (SignatureAlgorithm algo : SignatureAlgorithm.values())
        {
            if (algo.getEncryptionAlgorithm() == encryptionAlgorithm &&
                    algo.getDigestAlgorithm() == digestAlgorithm) {
                return algo;
            }
        }

        throw new IllegalArgumentException("Unsupported algorithm combination: " + encryptionAlgorithm + " / " + digestAlgorithm);
    }
}
