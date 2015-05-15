package com.novaordis.security.key;

import org.junit.Test;

import java.security.PublicKey;
import java.security.cert.Certificate;

import static org.junit.Assert.assertEquals;

public class SyntheticPrivateKeyTest
{
    // Constants -------------------------------------------------------------------------------------------------------

    // Static ----------------------------------------------------------------------------------------------------------

    // Attributes ------------------------------------------------------------------------------------------------------

    // Constructors ----------------------------------------------------------------------------------------------------

    // Public ----------------------------------------------------------------------------------------------------------

    @Test
    public void getCertificateChain_static() throws Exception
    {
        SyntheticPrivateKey spk = new SyntheticPrivateKey();

        Certificate[] certs = SyntheticPrivateKey.getCertificateChain(spk);

        assertEquals(1, certs.length);

        SyntheticCertificate sc = (SyntheticCertificate)certs[0];

        PublicKey pk = sc.getPublicKey();

        SyntheticPublicKey spbk = (SyntheticPublicKey)pk;

        assertEquals(spk.getId(), spbk.getId());
    }

    @Test
    public void getCertificateChain() throws Exception
    {
        SyntheticPrivateKey spk = new SyntheticPrivateKey();

        Certificate[] certs = spk.getCertificateChain();

        assertEquals(1, certs.length);

        SyntheticCertificate sc = (SyntheticCertificate)certs[0];

        PublicKey pk = sc.getPublicKey();

        SyntheticPublicKey spbk = (SyntheticPublicKey)pk;

        assertEquals(spk.getId(), spbk.getId());

        Certificate[] certs2 = SyntheticPrivateKey.getCertificateChain(spk);

        assertEquals(1, certs2.length);

        assertEquals(((SyntheticPublicKey)((SyntheticCertificate)certs[0]).getPublicKey()).getId(),
            ((SyntheticPublicKey)((SyntheticCertificate)certs2[0]).getPublicKey()).getId());
    }

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------


}
