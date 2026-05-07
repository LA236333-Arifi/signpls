package be.train.demo.demo.models;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class SimpleSignatureResponse
{
    @NotBlank
    String pdfBase64;

    @NotBlank
    String signatureValueBase64;

    @NotBlank
    String messageDigestBase64;
}
