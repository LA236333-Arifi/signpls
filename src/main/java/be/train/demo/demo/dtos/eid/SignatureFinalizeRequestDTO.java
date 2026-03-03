package be.train.demo.demo.dtos.eid;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
public class SignatureFinalizeRequestDTO
{
    @Getter @Setter @NotBlank
    @JsonProperty("signature")
    String signatureBase64;

    @Getter @Setter @JsonProperty("signatureAlgorithm")
    SignatureAlgorithmDTO signatureAlgorithmDTO;
}
