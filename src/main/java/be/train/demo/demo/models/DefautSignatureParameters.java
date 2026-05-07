package be.train.demo.demo.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class DefautSignatureParameters
{
    @NotBlank
    private String pdfBase64;

    @NotBlank
    private String hashFunction;
}
