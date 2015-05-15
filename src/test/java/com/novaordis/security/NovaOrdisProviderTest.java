package com.novaordis.security;

import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.Test;
import sun.security.jca.ProviderList;
import sun.security.jca.Providers;

import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;


public class NovaOrdisProviderTest
{
    // Constants -------------------------------------------------------------------------------------------------------

    private static final Logger log = Logger.getLogger(NovaOrdisProviderTest.class);

    // Static ----------------------------------------------------------------------------------------------------------

    // Attributes ------------------------------------------------------------------------------------------------------

    private boolean providerAdded;

    // Constructors ----------------------------------------------------------------------------------------------------

    // Public ----------------------------------------------------------------------------------------------------------

    //
    // KeyStore
    //

    @After
    public void removeProvider() throws Exception
    {
        if (!providerAdded)
        {
            // nothing to do
            return;
        }

        Provider[] providersBefore = Security.getProviders();
        Security.removeProvider(NovaOrdisProvider.PROVIDER_NAME);
        log.info("provider removed");
        providerAdded = false;

        Provider[] providersAfter = Security.getProviders();

        assertEquals(providersAfter.length, providersBefore.length - 1);
    }

    @Test
    public void registrationOnLastPosition() throws Exception
    {
        assertNull(Security.getProvider(NovaOrdisProvider.PROVIDER_NAME));

        Provider[] providersBefore = Security.getProviders();

        Provider p = new NovaOrdisProvider();
        Security.addProvider(p);
        providerAdded = true;

        Provider[] providersAfter = Security.getProviders();

        assertEquals(providersAfter.length, providersBefore.length + 1);

        // make sure we did not disturbed the already installed providers

        for(int i = 0; i < providersBefore.length; i ++)
        {
            assertEquals(providersBefore[i], providersAfter[i]);
        }

        Provider p2 = providersAfter[providersBefore.length];

        assertEquals(p, p2);
        assertEquals(NovaOrdisProvider.PROVIDER_NAME, p2.getName());
        assertEquals(NovaOrdisProvider.PROVIDER_INFO, p2.getInfo());
        assertEquals(NovaOrdisProvider.PROVIDER_VERSION, p2.getVersion(), 0.0001);
    }

    @Test
    public void keyStore_getInstance_ForType() throws Exception
    {
        assertNull(Security.getProvider(NovaOrdisProvider.PROVIDER_NAME));
        Provider p = new NovaOrdisProvider();
        Security.addProvider(p);
        providerAdded = true;

        KeyStore ks = KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE);

        assertEquals(NovaOrdisProvider.KEYSTORE_TYPE, ks.getType());
        assertEquals(p, ks.getProvider());
    }

    @Test
    public void keyStore_getInstance_ForProviderName() throws Exception
    {
        assertNull(Security.getProvider(NovaOrdisProvider.PROVIDER_NAME));
        Provider p = new NovaOrdisProvider();
        Security.addProvider(p);
        providerAdded = true;

        try
        {
            KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE, "NO-SUCH-PROVIDER");
            fail("should fail with NoSuchProviderException");
        }
        catch(NoSuchProviderException e)
        {
            log.info(e.getMessage());
        }

        KeyStore ks = KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE, NovaOrdisProvider.PROVIDER_NAME);

        assertEquals(NovaOrdisProvider.KEYSTORE_TYPE, ks.getType());
        assertEquals(p, ks.getProvider());
    }

    @Test
    public void keyStore_getInstance_ForProviderInstance() throws Exception
    {
        assertNull(Security.getProvider(NovaOrdisProvider.PROVIDER_NAME));

        // do NOT register the provider with the runtime
        Provider p = new NovaOrdisProvider();

        KeyStore ks = KeyStore.getInstance(NovaOrdisProvider.KEYSTORE_TYPE, p);

        assertEquals(NovaOrdisProvider.KEYSTORE_TYPE, ks.getType());
        assertEquals(p, ks.getProvider());

        assertNull(Security.getProvider(NovaOrdisProvider.PROVIDER_NAME));
    }

    //
    // KeyManagerFactory
    //

    @Test
    public void addProvider() throws Exception
    {
        //
        // before
        //

        ProviderList providerList = Providers.getProviderList();

        List<Provider> providers = providerList.providers();

        int providerCount = providers.size();

        for(Provider p: providers)
        {
            if (p.getName().equals(NovaOrdisProvider.PROVIDER_NAME))
            {
                fail(NovaOrdisProvider.PROVIDER_NAME + " not supposed to be registered");
            }
        }

        assertEquals(-1, providerList.getIndex(NovaOrdisProvider.PROVIDER_NAME));
        assertNull(providerList.getProvider(NovaOrdisProvider.PROVIDER_NAME));

        //
        // add
        //

        Provider p = new NovaOrdisProvider();

        ProviderList newProviderList = ProviderList.add(providerList, p);

        //
        // after
        //

        List<Provider> providers2 = newProviderList.providers();

        assertEquals(providers2.size(), providerCount + 1);

        for(int i = 0; i < providerCount; i ++)
        {
            assertEquals(providers.get(i), providers2.get(i));
        }

        assertEquals(p, providers2.get(providerCount));
        assertEquals(providerCount, newProviderList.getIndex(NovaOrdisProvider.PROVIDER_NAME));
        assertEquals(p, newProviderList.getProvider(NovaOrdisProvider.PROVIDER_NAME));
    }

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------


}
