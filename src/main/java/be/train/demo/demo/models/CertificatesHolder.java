package be.train.demo.demo.models;

import eu.europa.esig.dss.model.x509.CertificateToken;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
public class CertificatesHolder
{
    @Getter
    CertificateToken certificate;

    @Getter
    CertificateToken[] certificateChain;

    public boolean isValid()
    {
        return certificate != null;
    }
}
