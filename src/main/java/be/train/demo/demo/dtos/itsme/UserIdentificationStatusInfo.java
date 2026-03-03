package be.train.demo.demo.dtos.itsme;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
public class UserIdentificationStatusInfo
{
    @Getter @Setter @NotBlank
    @JsonProperty("certificate")
    private String certificate;

    @Getter @Setter @NotBlank
    @JsonProperty("fullCertificateChain")
    private String fullCertificateChain;
}
