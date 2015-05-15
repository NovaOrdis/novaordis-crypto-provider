package com.novaordis.security;

import com.novaordis.security.content.KeyStoreContent;
import com.novaordis.security.content.PrivateKeyHolder;
import com.novaordis.security.key.SyntheticCertificate;
import com.novaordis.security.key.SyntheticPrivateKey;
import com.novaordis.security.key.SyntheticPublicKey;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

public class KeyStoreSpiImpl extends KeyStoreSpi
{
    // Constants -------------------------------------------------------------------------------------------------------

    private static final Logger log = Logger.getLogger(KeyStoreSpiImpl.class);

    // Static ----------------------------------------------------------------------------------------------------------

    // Attributes ------------------------------------------------------------------------------------------------------

    // <alias - certificate chain>
    private Map<String, SyntheticCertificate> certificates;

    // <alias - private key holder>
    private Map<String, PrivateKeyHolder> privateKeys;

    // <alias - public key>
    private Map<String, SyntheticPublicKey> publicKeys;

    // Constructors ----------------------------------------------------------------------------------------------------

    public KeyStoreSpiImpl()
    {
        this.certificates = new HashMap<String, SyntheticCertificate>();
        this.privateKeys = new HashMap<String, PrivateKeyHolder>();
        this.publicKeys = new HashMap<String, SyntheticPublicKey>();
    }

    // KeyStoreSpi implementation --------------------------------------------------------------------------------------

    /**
     * From KeyStoreSpi javadoc:
     *
     * Returns the key associated with the given alias, using the given password to recover it. The key must have been
     * associated with the alias by a call to setKeyEntry, or by a call to setEntry with a PrivateKeyEntry or
     * SecretKeyEntry.
     *
     * @return the requested key, or null if the given alias does not exist or does not identify a key-related entry.
     *
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        PrivateKeyHolder h = privateKeys.get(alias);

        if (h == null)
        {
            // try public keys

            //noinspection UnnecessaryLocalVariable
            SyntheticPublicKey syntheticPublicKey = publicKeys.get(alias);

            return syntheticPublicKey;
        }

        if (h.getPassword() == null)
        {
            throw new UnrecoverableKeyException(
                "no password was set when the private key with alias \"" + alias + "\" was installed, cannot recover key");
        }

        if (!h.getPassword().equals(new String(password)))
        {
            throw new UnrecoverableKeyException("key password does not match");
        }

        return h.getPrivateKey();
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias)
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    /**
     * From KeyStoreSpi javadoc:
     *
     * Returns the certificate associated with the given alias. If the given alias name identifies an entry created by
     * a call to setCertificateEntry, or created by a call to setEntry with a TrustedCertificateEntry, then the trusted
     * certificate contained in that entry is returned.
     *
     * If the given alias name identifies an entry created by a call to setKeyEntry, or created by a call to setEntry
     * with a PrivateKeyEntry, then the first element of the certificate chain in that entry (if a chain exists)
     * is returned.
     *
     * @return the certificate, or null if the given alias does not exist or does not contain a certificate.
     */
    @Override
    public Certificate engineGetCertificate(String alias)
    {
        Certificate c;

        c = certificates.get(alias);

        if (c == null)
        {
            PrivateKeyHolder h = privateKeys.get(alias);

            if (h != null)
            {
                c = h.getPrivateKey().getCertificateChain()[0];
            }
        }

        return c;
    }

    @Override
    public Date engineGetCreationDate(String alias)
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    /**
     * From KeyStoreSpi javadoc:
     *
     * Assigns the given key (that has already been protected) to the given alias.
     *
     * <p>If the protected key is of type <code>java.security.PrivateKey</code>, it must be accompanied by a certificate
     * chain certifying the corresponding public key.
     *
     * <p>If the given alias already exists, the keystore information associated with it is overridden by the given key
     * (and possibly certificate chain).
     *
     * @param alias
     *          the alias name
     * @param key
     *          the key (in protected format) to be associated with the alias
     * @param chain
     *          the certificate chain for the corresponding public key (only useful if the protected key is of type
     *          <code>java.security.PrivateKey</code>).
     *
     * @exception KeyStoreException if this operation fails.
     */
    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException
    {
        // this implementation can only handle SyntheticKeys
        if (key instanceof PrivateKey)
        {
            if (!(key instanceof SyntheticPrivateKey))
            {
                throw new IllegalArgumentException("we can only handle SyntheticPrivateKeys, but we got a " + key);
            }

            if (chain == null || chain.length == 0)
            {
                throw new IllegalArgumentException("Private key must be accompanied by certificate chain");
            }

            privateKeys.put(alias, new PrivateKeyHolder((SyntheticPrivateKey)key, new String(password), chain));
        }
        else if (key instanceof PublicKey)
        {
            if (!(key instanceof SyntheticPublicKey))
            {
                throw new IllegalArgumentException("we can only handle SyntheticPublicKey, but we got a " + key);
            }

            publicKeys.put(alias, (SyntheticPublicKey)key);
        }
        else
        {
            throw new RuntimeException("NOT YET IMPLEMENTED");
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    /**
     * From KeyStoreSpi javadoc:
     *
     * Assigns the given certificate to the given alias. If the given alias identifies an existing entry created by a
     * call to setCertificateEntry, or created by a call to setEntry with a TrustedCertificateEntry, the trusted
     * certificate in the existing entry is overridden by the given certificate.
     *
     * @throws KeyStoreException if the given alias already exists and does not identify an entry containing a trusted
     * certificate, or this operation fails for some other reason.
     */

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException
    {
        if (!(cert instanceof SyntheticCertificate))
        {
            throw new IllegalArgumentException(cert + " is not a SyntheticCertificate");
        }
        certificates.put(alias, (SyntheticCertificate)cert);
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    public Enumeration<String> engineAliases()
    {
        return new Vector<String>().elements();
    }

    @Override
    public boolean engineContainsAlias(String alias)
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    public int engineSize()
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    public boolean engineIsKeyEntry(String alias)
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    public boolean engineIsCertificateEntry(String alias)
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert)
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    /**
     * @param stream null input stream is ignored - means "don't load anything".
     */
    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException
    {
        if (stream == null)
        {
            log.info(this + " NOT loading anything ...");
            return;
        }

        KeyStoreContent c = new KeyStoreContent();
        c.load(stream);
        privateKeys.clear();
        certificates.clear();

        for(String privateKeyAlias: c.getPrivateKeyAliases())
        {
            privateKeys.put(privateKeyAlias, c.getPrivateKeyHolder(privateKeyAlias));
        }

        log.info(this + " loaded content");
    }

    // Public ----------------------------------------------------------------------------------------------------------

    @Override
    public String toString()
    {
        return "NovaOrdis KeyStoreSpiImpl[" + Integer.toHexString(System.identityHashCode(this)) + "]";
    }

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------


}
