package be.train.demo.demo;


import be.train.demo.demo.utils.SignatureAlgorithmMapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SignatureAlgorithmMapperTest
{
    @Test
    public void test_FindCorrectSignatureAlgorithm()
    {
        EncryptionAlgorithm enc = EncryptionAlgorithm.RSA;
        DigestAlgorithm dig = DigestAlgorithm.SHA256;
        SignatureAlgorithm result = SignatureAlgorithmMapper.from(enc, dig);
        assertEquals(SignatureAlgorithm.RSA_SHA256, result);
    }
}
