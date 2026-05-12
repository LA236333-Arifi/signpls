package be.sbim.models;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class SignerInfo
{
    @NotBlank
    private String nom;

    @NotBlank
    private String prenom;

    private int signaturePosition = 1;
}
