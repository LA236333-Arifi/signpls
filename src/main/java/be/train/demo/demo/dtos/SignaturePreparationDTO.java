package be.train.demo.demo.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
public class SignaturePreparationDTO
{
    @Getter @Setter @NotBlank
    @JsonProperty("hash")
    private String hashValue;

    @Getter @Setter @NotBlank
    @JsonProperty("hashFunction")
    private String hashFunction;
}
