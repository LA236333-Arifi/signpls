package be.train.demo.demo.models;

import eu.europa.esig.dss.model.Digest;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SignatureRequest
{
    @NotNull
    Digest dataToSignDigest;

    @NotNull
    Date SigningDate;

    @NotBlank
    String certificateBase64;

    String certificateChainBase64;
}
