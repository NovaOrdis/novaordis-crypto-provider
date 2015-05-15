package com.novaordis.security;

import com.novaordis.security.content.KeyStoreContent;
import com.novaordis.security.key.SyntheticCertificate;
import com.novaordis.security.key.SyntheticPrivateKey;
import com.novaordis.security.key.SyntheticPublicKey;
import org.apache.log4j.Logger;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


public class KeyStoreSpiImplTest
{
    // Constants -------------------------------------------------------------------------------------------------------

    private static final Logger log = Logger.getLogger(KeyStoreSpiImplTest.class);

    // Static ----------------------------------------------------------------------------------------------------------

    // Attributes ------------------------------------------------------------------------------------------------------

    // Constructors ----------------------------------------------------------------------------------------------------

    // Public ----------------------------------------------------------------------------------------------------------

    @Test
    public void uninitializedKeyStore() throws Exception
    {
        KeyStore ks = KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE, new NovaOrdisProvider());

        try
        {
            ks.getCertificate("does-not-matter");
            fail("should fail with KeyStoreException because the store is not initialized");
        }
        catch(KeyStoreException e)
        {
            String msg = e.getMessage();
            log.info(msg);

            assertEquals("Uninitialized keystore", msg);
        }
    }

    @Test
    public void initializedKeyStore() throws Exception
    {
        KeyStore ks = KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE, new NovaOrdisProvider());

        // this "initializes"
        ks.load(null, "does not matter".toCharArray());

        // should return null, but not fail
        Certificate result = ks.getCertificate("no-such-alias");
        assertNull(result);
    }

    @Test
    public void setKeyEntry_NotASyntheticPrivateKey() throws Exception
    {
        KeyStore ks = KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE, new NovaOrdisProvider());
        ks.load(null, "does not matter".toCharArray());

        PrivateKey mock = new PrivateKey()
        {
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
        };

        Certificate[] certChain = SyntheticPrivateKey.getCertificateChain(new SyntheticPrivateKey());

        try
        {
            ks.setKeyEntry("test", mock, "does not matter".toCharArray(), certChain);
            fail("should fail with IllegalArgumentException");
        }
        catch(IllegalArgumentException e)
        {
            log.info(e.getMessage());
        }
    }

    // engineGetKey() --------------------------------------------------------------------------------------------------

    @Test
    public void engineGetKey_NoSuchAlias() throws Exception
    {
        KeyStore ks = KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE, new NovaOrdisProvider());
        ks.load(null, "does not matter".toCharArray());

        assertNull(ks.getKey("no-such-alias", "does not matter".toCharArray()));
    }

    @Test
    public void engineGetKey_PasswordsDoNotMatch() throws Exception
    {
        KeyStore ks = KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE, new NovaOrdisProvider());
        ks.load(null, "does not matter".toCharArray());

        SyntheticPrivateKey k = new SyntheticPrivateKey();
        ks.setKeyEntry("test-key", k, "test-passwd".toCharArray(), k.getCertificateChain());

        try
        {
            ks.getKey("test-key", "wrong password".toCharArray());
            fail("should have failed with UnrecoverableEntryException as passwords do not match");
        }
        catch(UnrecoverableEntryException e)
        {
            log.info(e.getMessage());
        }
    }

    @Test
    public void engineGetKey() throws Exception
    {
        KeyStore ks = KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE, new NovaOrdisProvider());
        ks.load(null, "does not matter".toCharArray());

        SyntheticPrivateKey k = new SyntheticPrivateKey();
        ks.setKeyEntry("test-key", k, "test-passwd".toCharArray(), k.getCertificateChain());

        SyntheticPrivateKey result = (SyntheticPrivateKey)ks.getKey("test-key", "test-passwd".toCharArray());

        assertEquals(k, result);
    }

    // engineSetCertificateEntry() -------------------------------------------------------------------------------------

    @Test
    public void engineSetCertificateEntry_NotASyntheticCertificate() throws Exception
    {
        KeyStore ks = KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE, new NovaOrdisProvider());
        ks.load(null, "does not matter".toCharArray());

        Certificate mock = new MockCertificate();

        try
        {
            ks.setCertificateEntry("test", mock);
            fail("should fail with IllegalArgumentException");
        }
        catch(IllegalArgumentException e)
        {
            log.info(e.getMessage());
        }
    }

    @Test
    public void engineSetCertificateEntry() throws Exception
    {
        KeyStore ks = KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE, new NovaOrdisProvider());
        ks.load(null, "does not matter".toCharArray());

        String id = UUID.randomUUID().toString();
        SyntheticCertificate sc = new SyntheticCertificate(new SyntheticPublicKey(id));

        ks.setCertificateEntry("testcert", sc);

        SyntheticCertificate result = (SyntheticCertificate)ks.getCertificate("testcert");

        assertEquals(id, result.getId());
    }


    // engineLoad ------------------------------------------------------------------------------------------------------

    @Test
    public void engineLoad_NullInputStream() throws Exception
    {
        KeyStore ks = KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE, new NovaOrdisProvider());

        // must not throw exception
        ks.load(null, "does not matter".toCharArray());

        assertNull(ks.getCertificate("no-such-certificate"));
    }

    @Test
    public void engineLoad_ValidInputStream() throws Exception
    {
        KeyStore ks = KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE, new NovaOrdisProvider());

        KeyStoreContent content = new KeyStoreContent();
        SyntheticPrivateKey pk = new SyntheticPrivateKey();
        content.add(pk, "test-alias", "test-password");

        String s = content.asString();

        ks.load(new ByteArrayInputStream(s.getBytes()), "does not matter".toCharArray());

        SyntheticPrivateKey result = (SyntheticPrivateKey)ks.getKey("test-alias", "test-password".toCharArray());

        assertEquals(pk.getId(), result.getId());
    }

    // engineSetKeyEntry() ---------------------------------------------------------------------------------------------

    @Test
    public void engineSetKeyEntry_PrivateKey_NotASyntheticKey() throws Exception
    {
        KeyStoreSpiImpl kss = new KeyStoreSpiImpl();

        try
        {
            kss.engineSetKeyEntry("test", new PrivateKey()
            {
                @Override
                public String getAlgorithm()
                {
                    return null;
                }

                @Override
                public String getFormat()
                {
                    return null;
                }

                @Override
                public byte[] getEncoded()
                {
                    return new byte[0];
                }
            }, "some password".toCharArray(), null);
            fail("should have failed with IllegalArgumentException because we're not installing a synthetic key");
        }
        catch(IllegalArgumentException e)
        {
            log.info(e.getMessage());
        }
    }

    @Test
    public void engineSetKeyEntry_PrivateKey_NoCertificates_1() throws Exception
    {
        KeyStoreSpiImpl kss = new KeyStoreSpiImpl();

        SyntheticPrivateKey syntheticPrivateKey = new SyntheticPrivateKey();

        try
        {
            kss.engineSetKeyEntry("test", syntheticPrivateKey, "some password".toCharArray(), null);
            fail("should have failed because we don't provide certificates");
        }
        catch(IllegalArgumentException e)
        {
            log.info(e.getMessage());
        }
    }

    @Test
    public void engineSetKeyEntry_PrivateKey_NoCertificates_2() throws Exception
    {
        KeyStoreSpiImpl kss = new KeyStoreSpiImpl();

        SyntheticPrivateKey syntheticPrivateKey = new SyntheticPrivateKey();

        try
        {
            kss.engineSetKeyEntry("test", syntheticPrivateKey, "some password".toCharArray(), new Certificate[0]);
            fail("should have failed because we don't provide certificates");
        }
        catch(IllegalArgumentException e)
        {
            log.info(e.getMessage());
        }
    }

    @Test
    public void engineSetKeyEntry_PrivateKey_WrongPasswordToRetrieveKey() throws Exception
    {
        KeyStoreSpiImpl kss = new KeyStoreSpiImpl();

        SyntheticPrivateKey syntheticPrivateKey = new SyntheticPrivateKey();
        SyntheticCertificate sc = new SyntheticCertificate(new SyntheticPublicKey(syntheticPrivateKey.getId()));

        kss.engineSetKeyEntry("test", syntheticPrivateKey, "some password".toCharArray(), new Certificate[] {sc});

        try
        {
            kss.engineGetKey("test", "wrong password".toCharArray());
            fail("should fail with UnrecoverableKeyException because we use the wrong password");
        }
        catch(UnrecoverableKeyException e)
        {
            log.info(e.getMessage());
        }
    }

    @Test
    public void engineSetKeyEntry_PrivateKey() throws Exception
    {
        KeyStoreSpiImpl kss = new KeyStoreSpiImpl();

        SyntheticPrivateKey syntheticPrivateKey = new SyntheticPrivateKey();
        SyntheticCertificate sc = new SyntheticCertificate(new SyntheticPublicKey(syntheticPrivateKey.getId()));

        kss.engineSetKeyEntry("test", syntheticPrivateKey, "some password".toCharArray(), new Certificate[] {sc});

        Key k = kss.engineGetKey("test", "some password".toCharArray());

        assertNotNull(k);

        assertTrue(k instanceof SyntheticPrivateKey);

        assertEquals(syntheticPrivateKey, k);
    }

    @Test
    public void engineSetKeyEntry_PublicKey_NotASyntheticKey() throws Exception
    {
        KeyStoreSpiImpl kss = new KeyStoreSpiImpl();

        try
        {
            kss.engineSetKeyEntry("test", new PublicKey()
            {
                @Override
                public String getAlgorithm()
                {
                    return null;
                }

                @Override
                public String getFormat()
                {
                    return null;
                }

                @Override
                public byte[] getEncoded()
                {
                    return new byte[0];
                }
            }, null, null);
            fail("should have failed with IllegalArgumentException because we're not installing a synthetic key");
        }
        catch(IllegalArgumentException e)
        {
            log.info(e.getMessage());
        }
    }

    @Test
    public void engineSetKeyEntry_PublicKey() throws Exception
    {
        KeyStoreSpiImpl kss = new KeyStoreSpiImpl();

        SyntheticPublicKey syntheticPublicKey = new SyntheticPublicKey("id0");

        kss.engineSetKeyEntry("test", syntheticPublicKey, null, null);

        Key k = kss.engineGetKey("test", null);

        assertNotNull(k);

        assertTrue(k instanceof SyntheticPublicKey);

        assertEquals(syntheticPublicKey, k);
    }

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------

    private class MockCertificate extends Certificate
    {
        MockCertificate()
        {
            super("TEST");
        }

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
        public String toString()
        {
            return "MockCertificate";
        }

        @Override
        public PublicKey getPublicKey()
        {
            throw new RuntimeException("NOT YET IMPLEMENTED");
        }
    }
}
