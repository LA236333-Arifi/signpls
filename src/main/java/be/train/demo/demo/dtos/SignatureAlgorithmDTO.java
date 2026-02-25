package be.train.demo.demo.dtos;

import be.train.demo.demo.utils.SignatureAlgorithmMapper;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import java.util.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignatureAlgorithmDTO
{

    @Getter @JsonProperty("cryptoAlgorithm")
    private String cryptoAlgorithm;

    @Getter @JsonProperty("hashFunction")
    private String hashFunction;

    @Getter @JsonProperty("paddingScheme")
    private String paddingScheme;

    public void setCryptoAlgorithm(String cryptoAlgorithm)
    {
        if (!SignatureAlgorithmMapper.hasEncryptionAlgorithm(cryptoAlgorithm))
        {
            throw new IllegalArgumentException("The provided crypto algorithm is not supported");
        }

        this.cryptoAlgorithm = cryptoAlgorithm;
    }


    public void setHashFunction(String hashFunction)
    {
        if (!SignatureAlgorithmMapper.hasDigestAlgorithm(hashFunction))
        {
            throw new IllegalArgumentException("The provided hash function is not supported");
        }

        this.hashFunction = hashFunction;
    }

    public void setPaddingScheme(String paddingScheme)
    {
        if (!SignatureAlgorithmMapper.hasPaddingScheme(paddingScheme))
        {
            throw new IllegalArgumentException("The provided padding scheme is not supported");
        }

        this.paddingScheme = paddingScheme;
    }

}