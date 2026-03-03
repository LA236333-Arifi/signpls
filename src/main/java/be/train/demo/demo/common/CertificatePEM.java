package be.train.demo.demo.common;

import be.train.demo.demo.interfaces.ICertificateConverter;
import eu.europa.esig.dss.spi.DSSUtils;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@NoArgsConstructor
@AllArgsConstructor
public class CertificatePEM implements ICertificateConverter
{
    @Getter @Setter @NotBlank
    private String certificatePem;

    public X509Certificate convertToX509Certificate() throws CertificateException
    {
        byte[] certificateBytes = DSSUtils.convertToDER(certificatePem);
        InputStream inStream = new ByteArrayInputStream(certificateBytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(inStream);
    }
}
