package be.train.demo.demo.interfaces;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public interface ICertificateConverter
{
    X509Certificate convertToX509Certificate() throws CertificateException;
}
