package be.train.demo.demo.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
public class SignatureFinalizeResponseDTO
{
    @Getter @Setter @JsonProperty("message")
    String message;

    @Getter @Setter @JsonProperty("success")
    boolean success;
}
