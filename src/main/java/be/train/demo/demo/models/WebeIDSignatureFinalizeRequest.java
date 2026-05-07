package be.train.demo.demo.models;

import be.train.demo.demo.dtos.eid.SignatureAlgorithmDTO;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class WebeIDSignatureFinalizeRequest
{
    @Valid
    DefautSignatureParameters signatureParameters;

    @NotBlank
    @JsonProperty("signature")
    String signatureBase64;

    @NotBlank
    @JsonProperty("certificate")
    private String certificateBase64;

    @NotBlank
    private String signingDate;

    @NotBlank
    @JsonProperty("hash")
    private String hashValue;

    @JsonProperty("signatureAlgorithm")
    SignatureAlgorithmDTO signatureAlgorithmDTO;

    public Date getSigningDate()
    {
        try
        {
            SimpleDateFormat formateur = new SimpleDateFormat("yyyyMMdd");
            Date date = formateur.parse(signingDate);
            return date;
        }
        catch (ParseException e)
        {
            e.printStackTrace();
            return new Date();
        }
    }
}
