package be.train.demo.demo.models;

import eu.europa.esig.dss.model.Digest;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.util.Date;

@NoArgsConstructor
@AllArgsConstructor
public class SignatureRequest
{
    @Getter @Setter @NotNull
    Digest dataToSignDigest;

    @Getter @Setter @NotNull
    Date SigningDate;

    @Getter @Setter @NotBlank
    String certificateBase64;

    @Getter @Setter
    String certificateChainBase64;
}
