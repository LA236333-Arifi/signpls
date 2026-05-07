package be.train.demo.demo.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import eu.europa.esig.dss.model.Digest;
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
public class WebeIDSignaturePreparationResponse
{
    @NotBlank
    @JsonProperty("hash")
    private String hashValue;

    @NotBlank
    @JsonProperty("hashFunction")
    private String hashFunction;
}
