package be.train.demo.demo.models;

import be.train.demo.demo.utils.SignConstants;
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

    private String hashFunction = SignConstants.SHA_256;
}
