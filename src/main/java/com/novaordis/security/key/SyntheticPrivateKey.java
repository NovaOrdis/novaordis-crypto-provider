package com.novaordis.security.key;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.UUID;

public class SyntheticPrivateKey implements PrivateKey
{
    // Constants -------------------------------------------------------------------------------------------------------

    // Static ----------------------------------------------------------------------------------------------------------

    public static Certificate[] getCertificateChain(SyntheticPrivateKey pk)
    {
        return new Certificate[] { new SyntheticCertificate(new SyntheticPublicKey(pk.getId()))};
    }

    // Attributes ------------------------------------------------------------------------------------------------------

    private String id;

    // Constructors ----------------------------------------------------------------------------------------------------

    public SyntheticPrivateKey()
    {
        this.id = UUID.randomUUID().toString();
    }

    public SyntheticPrivateKey(String id)
    {
        this.id = id;
    }

    // PrivateKey implementation ---------------------------------------------------------------------------------------

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

    /**
     * A public/private key pair share the same unique id. The private key's id is generated during creation.
     */
    public String getId()
    {
        return id;
    }

    public Certificate[] getCertificateChain()
    {
        return SyntheticPrivateKey.getCertificateChain(this);
    }

    @Override
    public String toString()
    {
        return "SyntheticPrivateKey[" + id + "]";
    }

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------


}
