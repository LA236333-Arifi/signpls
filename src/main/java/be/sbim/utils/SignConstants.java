package be.sbim.utils;

import eu.europa.esig.dss.enumerations.SignatureLevel;

public class SignConstants
{
    static public final String SHA_256 = "SHA256";
    static public final int MaxDocumentsToSignInOneBatch = 50;
    static public final String AppName = "SignElec";
    static public final SignatureLevel DefaultSignatureLevel = SignatureLevel.PAdES_BASELINE_B;

    // Mise en page de la grille de signatures (A4 portrait : 595 x 842 pts)
    static public final float PageWidth         = 595f;
    static public final float PageHeight        = 842f;
    static public final int   GridCols          = 3;
    static public final int   GridRows          = 5;
    static public final int   SignaturesPerPage = GridCols * GridRows;
    static public final float PageMargin        = 30f;
    static public final float CellPadding       = 8f;
}
