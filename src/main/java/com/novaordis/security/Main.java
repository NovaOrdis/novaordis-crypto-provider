package com.novaordis.security;

import com.novaordis.security.key.SyntheticPrivateKey;
import sun.security.jca.ProviderList;
import sun.security.jca.Providers;

import javax.crypto.Cipher;
import java.security.Provider;
import java.security.Security;

public class Main
{
    // Constants -------------------------------------------------------------------------------------------------------

    // Static ----------------------------------------------------------------------------------------------------------

    public static void main(String[] args) throws Exception
    {

        // this sequence simulates BouncyCastle registration in PicketLink

        Provider novaOrdisProvider = new NovaOrdisProvider();

        Provider installed = Security.getProvider(novaOrdisProvider.getName());

        if (installed == null)
        {
            //
            // Install the provider after the SUN provider or on position 2.
            //
            int ret = 0;
            Provider[] providers = Security.getProviders();
            for (int i = 0; i < providers.length; i++)
            {
                if ("SUN".equals(providers[i].getName()))
                {
                    ret = Security.insertProviderAt(novaOrdisProvider, i + 2);
                    break;
                }
            }

            if (ret == 0)
            {
                Security.insertProviderAt(novaOrdisProvider, 2);
            }
        }

        //ProviderList oldProviderList = Providers.getProviderList();
        //ProviderList newProviderList = ProviderList.add(oldProviderList, novaOrdisProvider);
        //Providers.setProviderList(newProviderList);

        Provider[] providers = Security.getProviders();

        Cipher c = Cipher.getInstance(NovaOrdisProvider.CRYPTOGRAPHIC_ALGORITHM);

        c.init(Cipher.UNWRAP_MODE, new SyntheticPrivateKey());

        System.out.println(".");
    }

    // Attributes ------------------------------------------------------------------------------------------------------

    // Constructors ----------------------------------------------------------------------------------------------------

    // Public ----------------------------------------------------------------------------------------------------------

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------

}
