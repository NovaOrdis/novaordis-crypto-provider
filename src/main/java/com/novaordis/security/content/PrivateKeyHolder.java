package com.novaordis.security.content;

import com.novaordis.security.key.SyntheticPrivateKey;

import java.io.InputStream;
import java.security.cert.Certificate;

public class PrivateKeyHolder
{
    // Constants -------------------------------------------------------------------------------------------------------

    // Static ----------------------------------------------------------------------------------------------------------

    // Attributes ------------------------------------------------------------------------------------------------------

    private SyntheticPrivateKey privateKey;
    private String password;
    private Certificate[] certificateChain;

    // Constructors ----------------------------------------------------------------------------------------------------

    public PrivateKeyHolder()
    {
    }

    public PrivateKeyHolder(SyntheticPrivateKey privateKey, String password, Certificate[] certificateChain)
    {
        this.privateKey = privateKey;
        this.password = password;
        this.certificateChain = certificateChain;
    }

    // Public ----------------------------------------------------------------------------------------------------------

    public SyntheticPrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public String getPassword()
    {
        return password;
    }

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------


}
