package com.novaordis.security.key;

import java.security.PublicKey;

public class SyntheticPublicKey implements PublicKey
{
    // Constants -------------------------------------------------------------------------------------------------------

    // Static ----------------------------------------------------------------------------------------------------------

    // Attributes ------------------------------------------------------------------------------------------------------

    private String id;

    // Constructors ----------------------------------------------------------------------------------------------------

    /**
     * A public/private key pair share the same unique id.
     */
    public SyntheticPublicKey(String id)
    {
        this.id = id;
    }

    // PublicKey implementation ----------------------------------------------------------------------------------------

    @Override
    public String getAlgorithm()
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    public String getFormat()
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    public byte[] getEncoded()
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    // Public ----------------------------------------------------------------------------------------------------------

    public String getId()
    {
        return id;
    }

    @Override
    public String toString()
    {
        return "SyntheticPublicKey[" + id + "]";
    }

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------


}
