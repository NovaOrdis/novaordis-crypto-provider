package com.novaordis.security.content;

import com.novaordis.security.key.SyntheticPrivateKey;
import org.apache.log4j.Logger;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class KeyStoreContentTest
{
    // Constants -------------------------------------------------------------------------------------------------------

    private static final Logger log = Logger.getLogger(KeyStoreContentTest.class);

    // Static ----------------------------------------------------------------------------------------------------------

    // Attributes ------------------------------------------------------------------------------------------------------

    // Constructors ----------------------------------------------------------------------------------------------------

    // Public ----------------------------------------------------------------------------------------------------------

    @Test
    public void simplePrivateKey() throws Exception
    {
        KeyStoreContent c = new KeyStoreContent();
        SyntheticPrivateKey spk = new SyntheticPrivateKey();

        c.add(spk, "test-alias", "test-password");

        String s = c.asString();

        log.info(s);

        ByteArrayInputStream bais = new ByteArrayInputStream(s.getBytes());

        KeyStoreContent c2 = new KeyStoreContent();
        c2.load(bais);

        Set<String> pvtKeyAliases = c2.getPrivateKeyAliases();
        assertEquals(1, pvtKeyAliases.size());

        String alias = pvtKeyAliases.iterator().next();
        assertEquals("test-alias", alias);

        PrivateKeyHolder h = c2.getPrivateKeyHolder(alias);

        assertEquals("test-password", h.getPassword());
        assertEquals(spk.getId(), h.getPrivateKey().getId());
    }

    @Test
    public void commentsAndSimpleKey() throws Exception
    {
        String s =
                "# this is a comment\n" +
                "alias1, KEY, passwd1, id001\n" +
                "# this is another comment\n" +
                "alias2, KEY, passwd2, id002";

        KeyStoreContent c = new KeyStoreContent();
        c.load(new ByteArrayInputStream(s.getBytes()));

        Set<String> pvtKeyAliases = c.getPrivateKeyAliases();
        assertEquals(2, pvtKeyAliases.size());
        assertTrue(pvtKeyAliases.contains("alias1"));
        assertTrue(pvtKeyAliases.contains("alias2"));

        PrivateKeyHolder h = c.getPrivateKeyHolder("alias1");
        assertEquals("passwd1", h.getPassword());
        assertEquals(h.getPrivateKey().getId(), "id001");

        PrivateKeyHolder h2 = c.getPrivateKeyHolder("alias2");
        assertEquals("passwd2", h2.getPassword());
        assertEquals(h2.getPrivateKey().getId(), "id002");
    }

    @Test
    public void emptyLine() throws Exception
    {
        String s =
            "# this is a comment\n" +
                "\n" +
                "\n" +
                "alias1, KEY, passwd1, id001\n" +
                "\n";

        KeyStoreContent c = new KeyStoreContent();
        c.load(new ByteArrayInputStream(s.getBytes()));

        Set<String> pvtKeyAliases = c.getPrivateKeyAliases();
        assertEquals(1, pvtKeyAliases.size());
        assertTrue(pvtKeyAliases.contains("alias1"));

        PrivateKeyHolder h = c.getPrivateKeyHolder("alias1");
        assertEquals("passwd1", h.getPassword());
        assertEquals(h.getPrivateKey().getId(), "id001");
    }

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------


}
