package com.novaordis.security.key;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

public class SyntheticCertificate extends Certificate
{
    // Constants -------------------------------------------------------------------------------------------------------

    public static final String TYPE = "NO-CERT";

    // Static ----------------------------------------------------------------------------------------------------------

    // Attributes ------------------------------------------------------------------------------------------------------

    private SyntheticPublicKey publicKey;

    // Constructors ----------------------------------------------------------------------------------------------------

    public SyntheticCertificate(SyntheticPublicKey publicKey)
    {
        // default type "X.509"
        super(TYPE);
        this.publicKey = publicKey;
    }

    // Certificate overrides -------------------------------------------------------------------------------------------

    @Override
    public byte[] getEncoded() throws CertificateEncodingException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    public void verify(PublicKey key) throws
        CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws
        CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    public PublicKey getPublicKey()
    {
        return publicKey;
    }

    @Override
    public String toString()
    {
        return "SyntheticCertificate[" + getType() + "](" + publicKey + ")";
    }

    // Public ----------------------------------------------------------------------------------------------------------

    /**
     * @return the id of the enclosed public key.
     */
    public String getId()
    {
        return ((SyntheticPublicKey)getPublicKey()).getId();
    }

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------


}
