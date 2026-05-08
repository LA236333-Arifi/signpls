package be.train.demo.demo.models.WebeID;

import be.train.demo.demo.dtos.eid.SignatureAlgorithmDTO;
import be.train.demo.demo.models.DefautSignatureParameters;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class WebeIDSignaturePreparationRequest
{
    @Valid
    DefautSignatureParameters signatureParameters;

    @NotBlank
    @JsonProperty("certificate")
    private String certificateBase64;

    @JsonProperty("supportedSignatureAlgorithms")
    private List<SignatureAlgorithmDTO> supportedSignatureAlgorithms;

    public List<String> getSupportedHashFunctionNames()
    {
        return supportedSignatureAlgorithms == null ? new ArrayList<>() : supportedSignatureAlgorithms
                .stream()
                .map(SignatureAlgorithmDTO::getHashFunction)
                .distinct()
                .collect(Collectors.toList());
    }
}
