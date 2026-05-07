package be.train.demo.demo.models;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class SimpleSignatureRequest
{
    @Valid
    DefautSignatureParameters signatureParameters;

    private boolean bDecorationPdf;
}
