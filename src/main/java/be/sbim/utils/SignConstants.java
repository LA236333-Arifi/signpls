package be.sbim.utils;

import eu.europa.esig.dss.enumerations.SignatureLevel;

public class SignConstants
{
    static public final String SHA_256 = "SHA256";
    static public final int MaxDocumentsToSignInOneBatch = 50;
    static public final String AppName = "SignElec";
    static public final SignatureLevel DefaultSignatureLevel = SignatureLevel.PAdES_BASELINE_B;
}
