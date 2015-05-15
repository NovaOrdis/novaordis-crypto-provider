package com.novaordis.security;

import com.novaordis.security.cryptography.CipherSpiImpl;

import java.security.Provider;

public class NovaOrdisProvider extends Provider
{
    // Constants -------------------------------------------------------------------------------------------------------

    public static final String PROVIDER_NAME = "NovaOrdis Provider";
    public static final String PROVIDER_INFO = "NovaOrdis Provider, part of Nova Ordis Cryptography Services Provider";
    public static final double PROVIDER_VERSION = 1.0;

    public static final String KEYSTORE_TYPE = "NO";
    public static final String KEY_MANAGER_FACTORY_ALGORITHM_NAME = "NOKMA";
    public static final String CRYPTOGRAPHIC_ALGORITHM = "NOCRYPTO";


    // Static ----------------------------------------------------------------------------------------------------------

    // Attributes ------------------------------------------------------------------------------------------------------

    // Constructors ----------------------------------------------------------------------------------------------------

    /**
     * @see Provider#Provider(String, double, String)
     */
    public NovaOrdisProvider()
    {
        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);

        //
        // Key Store functionality
        //

        // declare the SPI class that backs up a "NO" type of KeyStore
        put("KeyStore." + KEYSTORE_TYPE, KeyStoreSpiImpl.class.getName());

        //
        // KeyManagerFactory functionality
        //

        put("KeyManagerFactory." + KEY_MANAGER_FACTORY_ALGORITHM_NAME, KeyManagerFactorySpiImpl.class.getName());

        //
        // Cryptographic services (cipher, message digest, etc)
        //

        //put("Cipher." + CRYPTOGRAPHIC_ALGORITHM, CipherSpiImpl.class.getName());


        Service cipherService =
            new Service(this, "Cipher", CRYPTOGRAPHIC_ALGORITHM, CipherSpiImpl.class.getName(), null, null);

        putService(cipherService);

    }

    /**
     * @param uselessArgument we need to declare this in the constructor signature to be able to navigate the
     *                        logic implemented in JaasSecurityDomain.loadKeyAndTrustStore().
     */
    public NovaOrdisProvider(String uselessArgument)
    {
        this();
    }

    // Provider overrides ----------------------------------------------------------------------------------------------

    @Override
    public Service getService(String type, String algorithm)
    {
        //noinspection UnnecessaryLocalVariable
        Service s = super.getService(type, algorithm);
        return s;
    }

    // Public ----------------------------------------------------------------------------------------------------------

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------


}
