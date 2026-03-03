package be.train.demo.demo.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@AllArgsConstructor
@NoArgsConstructor
public class SignaturePreparationRequestDTO
{
    @Getter @Setter @NotBlank
    @JsonProperty("certificate")
    private String certificateBase64;

    @Getter @Setter
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
