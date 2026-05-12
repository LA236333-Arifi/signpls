package be.sbim.models.WebeID;

import be.sbim.models.DefautSignatureParameters;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class WebeIDSignatureFinalizeRequest
{
    @Valid
    DefautSignatureParameters signatureParameters;

    @NotBlank
    @JsonProperty("signature")
    String signatureBase64;

    @JsonProperty("signatureAlgorithm")
    SignatureAlgorithmDTO signatureAlgorithmDTO;

    @NotBlank
    @JsonProperty("certificate")
    private String certificateBase64;

    @NotNull
    private Date signingDate;

    @NotBlank
    @JsonProperty("hash")
    private String hashValue;
}
