package com.novaordis.security.content;

import com.novaordis.security.key.SyntheticPrivateKey;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * Format:
 *
 * TODO: will break if the alias or passwords contain commas
 *
 * alias, KEY|CERT, key-password, id
 */
public class KeyStoreContent
{
    // Constants -------------------------------------------------------------------------------------------------------

    // Static ----------------------------------------------------------------------------------------------------------

    // Attributes ------------------------------------------------------------------------------------------------------

    // alias - privateKeyHolder
    private Map<String, PrivateKeyHolder> privateKeys;

    // Constructors ----------------------------------------------------------------------------------------------------

    public KeyStoreContent()
    {
        this.privateKeys = new HashMap<String, PrivateKeyHolder>();
    }

    // Public ----------------------------------------------------------------------------------------------------------

    public void load(InputStream is) throws IOException
    {
        BufferedReader br = null;

        try
        {
            br = new BufferedReader(new InputStreamReader(is));

            String line;

            while((line = br.readLine()) != null)
            {
                line = line.trim();
                if (line.startsWith("#") || line.isEmpty())
                {
                    // comment
                    continue;
                }

                StringTokenizer st = new StringTokenizer(line, ",", false);

                if (!st.hasMoreTokens())
                {
                    throw new IOException("alias missing");
                }

                String alias = st.nextToken().trim();

                if (!st.hasMoreTokens())
                {
                    throw new IOException("KEY|CERT missing");
                }

                String s = st.nextToken().trim();

                if ("KEY".equals(s))
                {
                    if (!st.hasMoreTokens())
                    {
                        throw new IOException("key password missing");
                    }

                    String password = st.nextToken().trim();

                    if (!st.hasMoreTokens())
                    {
                        throw new IOException("key id missing");
                    }

                    String id = st.nextToken().trim();

                    SyntheticPrivateKey privateKey = new SyntheticPrivateKey(id);
                    PrivateKeyHolder h = new PrivateKeyHolder(privateKey, password, privateKey.getCertificateChain());
                    privateKeys.put(alias, h);
                }
                else if ("CERT".equals(s))
                {
                    throw new RuntimeException("NOT YET IMPLEMENTED");
                }
                else
                {
                    throw new IOException("expecting KEY|CERT and got \"" + s + "\"");
                }

            }
        }
        finally
        {
            if (br != null)
            {
                br.close();
            }
        }
    }

    public String asString()
    {
        StringBuilder sb = new StringBuilder();

        for(String privateKeyAlias: privateKeys.keySet())
        {
            PrivateKeyHolder h = privateKeys.get(privateKeyAlias);

            sb.append(privateKeyAlias).append(", ");
            sb.append("KEY").append(", ");
            sb.append(h.getPassword()).append(", ");
            sb.append(h.getPrivateKey().getId());
            sb.append("\n");
        }

        return sb.toString();
    }

    public void add(SyntheticPrivateKey privateKey, String alias, String password)
    {
        privateKeys.put(alias, new PrivateKeyHolder(privateKey, password, privateKey.getCertificateChain()));
    }

    public Set<String> getPrivateKeyAliases()
    {
        return privateKeys.keySet();
    }

    public PrivateKeyHolder getPrivateKeyHolder(String alias)
    {
        return privateKeys.get(alias);
    }

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------


}
