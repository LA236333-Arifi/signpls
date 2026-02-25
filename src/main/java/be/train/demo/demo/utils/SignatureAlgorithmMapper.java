package be.train.demo.demo.utils;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class SignatureAlgorithmMapper
{
    private static final Map<String, EncryptionAlgorithm> SUPPORTED_CRYPTO_ALGOS = new HashMap<>();
    private static final Map<String, DigestAlgorithm> SUPPORTED_HASH_FUNCTIONS = new HashMap<>();
    private static final Set<String> SUPPORTED_PADDING_SCHEMES = new HashSet<>();
    private static final Map<DigestAlgorithm, String> CONVERSION_HASH_FUNCTIONS = new HashMap<>();
    private static final Map<EncryptionAlgorithm, String> CONVERSION_ENCRYPTION_ALGO = new HashMap<>();

    static
    {
        SUPPORTED_CRYPTO_ALGOS.put("RSA", EncryptionAlgorithm.RSA);
        SUPPORTED_CRYPTO_ALGOS.put("ECC", EncryptionAlgorithm.PLAIN_ECDSA);

        SUPPORTED_HASH_FUNCTIONS.put("SHA-224", DigestAlgorithm.SHA224);
        SUPPORTED_HASH_FUNCTIONS.put("SHA-256", DigestAlgorithm.SHA256);
        SUPPORTED_HASH_FUNCTIONS.put("SHA-384", DigestAlgorithm.SHA384);
        SUPPORTED_HASH_FUNCTIONS.put("SHA-512", DigestAlgorithm.SHA512);
        SUPPORTED_HASH_FUNCTIONS.put("SHA3-224", DigestAlgorithm.SHA3_224);
        SUPPORTED_HASH_FUNCTIONS.put("SHA3-256", DigestAlgorithm.SHA3_256);
        SUPPORTED_HASH_FUNCTIONS.put("SHA3-384", DigestAlgorithm.SHA3_384);
        SUPPORTED_HASH_FUNCTIONS.put("SHA3-512", DigestAlgorithm.SHA3_512);

        SUPPORTED_PADDING_SCHEMES.add("NONE");
        SUPPORTED_PADDING_SCHEMES.add("PKCS1.5");
        SUPPORTED_PADDING_SCHEMES.add("PSS");
    }

    static
    {
        CONVERSION_HASH_FUNCTIONS.put(DigestAlgorithm.SHA224, "SHA-224");
        CONVERSION_HASH_FUNCTIONS.put(DigestAlgorithm.SHA256, "SHA-256");
        CONVERSION_HASH_FUNCTIONS.put(DigestAlgorithm.SHA384, "SHA-384");
        CONVERSION_HASH_FUNCTIONS.put(DigestAlgorithm.SHA512, "SHA-512");

        CONVERSION_HASH_FUNCTIONS.put(DigestAlgorithm.SHA3_224, "SHA3-224");
        CONVERSION_HASH_FUNCTIONS.put(DigestAlgorithm.SHA3_256, "SHA3-256");
        CONVERSION_HASH_FUNCTIONS.put(DigestAlgorithm.SHA3_384, "SHA3-384");
        CONVERSION_HASH_FUNCTIONS.put(DigestAlgorithm.SHA3_512, "SHA3-512");

        CONVERSION_ENCRYPTION_ALGO.put(EncryptionAlgorithm.RSA, "RSA");
        CONVERSION_ENCRYPTION_ALGO.put(EncryptionAlgorithm.PLAIN_ECDSA, "ECC");
    }

    public static String getDigestAlgorithm(DigestAlgorithm digestAlgorithm)
    {
        return CONVERSION_HASH_FUNCTIONS.get(digestAlgorithm);
    }

    public static String getEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm)
    {
        return CONVERSION_ENCRYPTION_ALGO.get(encryptionAlgorithm);
    }

    public static EncryptionAlgorithm getEncryptionAlgorithm(String encryptionAlgorithm)
    {
        return SUPPORTED_CRYPTO_ALGOS.get(encryptionAlgorithm);
    }

    public static DigestAlgorithm getDigestAlgorithm(String digestAlgorithm)
    {
        return SUPPORTED_HASH_FUNCTIONS.get(digestAlgorithm);
    }

    public static boolean hasEncryptionAlgorithm(String encryptionAlgorithm)
    {
        return SUPPORTED_CRYPTO_ALGOS.containsKey(encryptionAlgorithm);
    }

    public static boolean hasDigestAlgorithm(String digestAlgorithm)
    {
        return SUPPORTED_HASH_FUNCTIONS.containsKey(digestAlgorithm);
    }

    public static boolean hasPaddingScheme(String paddingScheme)
    {
        return SUPPORTED_PADDING_SCHEMES.contains(paddingScheme);
    }

    public static SignatureAlgorithm from(String encryptionAlgorithm, String digestAlgorithm)
    {
        EncryptionAlgorithm cryptoAlgo = getEncryptionAlgorithm(encryptionAlgorithm);
        DigestAlgorithm hashFunction = getDigestAlgorithm(digestAlgorithm);

        return from(cryptoAlgo, hashFunction);
    }

    public static SignatureAlgorithm from(EncryptionAlgorithm encryptionAlgorithm, DigestAlgorithm digestAlgorithm)
    {
        for (SignatureAlgorithm algo : SignatureAlgorithm.values())
        {
            if (algo.getEncryptionAlgorithm() == encryptionAlgorithm &&
                    algo.getDigestAlgorithm() == digestAlgorithm)
            {
                return algo;
            }
        }

        throw new IllegalArgumentException("Unsupported algorithm combination: " + encryptionAlgorithm + " / " + digestAlgorithm);
    }
}
