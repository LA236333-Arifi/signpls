package be.train.demo.demo.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

public class CertificateDTO
{
    @Getter @Setter @NotBlank
    @JsonProperty("certificate")
    private String certificateBase64;

    @Getter @Setter @JsonProperty("supportedSignatureAlgorithms")
    private List<SignatureAlgorithmDTO> supportedSignatureAlgorithms;

    public X509Certificate toX509Certificate() throws CertificateException
    {
        byte[] certificateBytes = Base64.getDecoder().decode(certificateBase64);
        InputStream inStream = new ByteArrayInputStream(certificateBytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(inStream);
    }

    public List<String> getSupportedHashFunctionNames()
    {
        return supportedSignatureAlgorithms == null ? new ArrayList<>() : supportedSignatureAlgorithms
                .stream()
                .map(SignatureAlgorithmDTO::getHashFunction)
                .distinct()
                .collect(Collectors.toList());
    }
}
