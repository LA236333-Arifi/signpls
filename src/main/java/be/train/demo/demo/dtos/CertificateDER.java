package be.train.demo.demo.dtos;

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
import java.util.Base64;

@AllArgsConstructor
@NoArgsConstructor
public class CertificateDER extends GenericCertificate
{
    @Getter @Setter @NotBlank
    private String certificateBase64;

    public X509Certificate convertToX509Certificate() throws CertificateException
    {
        byte[] certificateBytes = Base64.getDecoder().decode(certificateBase64);
        InputStream inStream = new ByteArrayInputStream(certificateBytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(inStream);
    }
}
