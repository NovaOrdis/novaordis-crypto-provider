package com.novaordis.security.key;

import com.novaordis.security.key.SyntheticCertificate;
import com.novaordis.security.key.SyntheticPrivateKey;
import org.junit.Test;

import java.security.cert.Certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;


public class SyntheticCertificateTest
{
    // Constants -------------------------------------------------------------------------------------------------------

    // Static ----------------------------------------------------------------------------------------------------------

    // Attributes ------------------------------------------------------------------------------------------------------

    // Constructors ----------------------------------------------------------------------------------------------------

    // Public ----------------------------------------------------------------------------------------------------------

    @Test
    public void privateKey_getCertificate() throws Exception
    {
        SyntheticPrivateKey spk = new SyntheticPrivateKey();

        Certificate[] certs1 = spk.getCertificateChain();
        Certificate[] certs2 = spk.getCertificateChain();

        assertEquals(1, certs1.length);
        assertEquals(1, certs2.length);

        assertEquals(((SyntheticCertificate)certs1[0]).getId(), ((SyntheticCertificate)certs2[0]).getId());
    }

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------


}
