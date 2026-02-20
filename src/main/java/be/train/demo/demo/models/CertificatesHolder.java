package be.train.demo.demo.models;

import eu.europa.esig.dss.model.x509.CertificateToken;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
public class CertificatesHolder
{
    @Getter @Setter
    CertificateToken certificate;

    @Getter @Setter
    CertificateToken[] certificateChain;

    public boolean isValid()
    {
        return certificate != null;
    }
}
