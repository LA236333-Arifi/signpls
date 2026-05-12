package be.sbim.models;

import be.sbim.utils.SignConstants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class SimpleSignatureRequest
{
    @Valid @NotEmpty
    private List<DefautSignatureParameters> signatureParameters;

    @Valid
    SignerInfo signerInfo;

    private String hashFunction = SignConstants.SHA_256;
}
