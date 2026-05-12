package be.sbim.models.WebeID;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class WebeIDSignaturePreparationResponse
{
    @NotBlank
    @JsonProperty("hash")
    private String hashValue;

    @NotBlank
    @JsonProperty("hashFunction")
    private String hashFunction;

    @NotBlank
    private Date signingDate;
}
