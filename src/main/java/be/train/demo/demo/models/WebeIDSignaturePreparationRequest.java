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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class WebeIDSignaturePreparationRequest
{
    @Valid
    DefautSignatureParameters signatureParameters;

    @NotBlank
    private String signingDate;

    @NotBlank
    @JsonProperty("certificate")
    private String certificateBase64;

    @JsonProperty("supportedSignatureAlgorithms")
    private List<SignatureAlgorithmDTO> supportedSignatureAlgorithms;

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

    public List<String> getSupportedHashFunctionNames()
    {
        return supportedSignatureAlgorithms == null ? new ArrayList<>() : supportedSignatureAlgorithms
                .stream()
                .map(SignatureAlgorithmDTO::getHashFunction)
                .distinct()
                .collect(Collectors.toList());
    }
}
