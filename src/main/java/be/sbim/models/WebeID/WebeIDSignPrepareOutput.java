package be.sbim.models.WebeID;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class WebeIDSignPrepareOutput
{
    Digest messageDigest;

    Date signingDate;

    DigestAlgorithm digestAlgorithm;
}
