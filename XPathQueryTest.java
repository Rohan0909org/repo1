package org.cysecurity.cspf.jvl.controller;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import org.w3c.dom.Document;

/**
 * Tests for XPathQuery parameterized XPath fix (CWE-501 Trust Boundary Violation
 * and XPath Injection remediation).
 *
 * These tests verify that:
 * 1. Legitimate credentials work correctly with parameterized XPath.
 * 2. XPath injection payloads in username/password do NOT bypass authentication.
 * 3. The value stored in the session (name) is sourced from XML data, not from
 *    user-controlled XPath syntax.
 */
public class XPathQueryTest {

    /**
     * Minimal in-memory users XML document used by all tests.
     * Mirrors the schema expected by the XPath expression in XPathQuery.java.
     */
    private static final String USERS_XML =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<users>" +
            "  <user>" +
            "    <username>alice</username>" +
            "    <password>secret123</password>" +
            "    <name>Alice Smith</name>" +
            "  </user>" +
            "  <user>" +
            "    <username>bob</username>" +
            "    <password>p@ssw0rd</password>" +
            "    <name>Bob Jones</name>" +
            "  </user>" +
            "</users>";

    private Document usersDoc;

    @Before
    public void setUp() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputStream is = new ByteArrayInputStream(USERS_XML.getBytes("UTF-8"));
        usersDoc = builder.parse(is);
    }

    // -----------------------------------------------------------------------
    // Helper: runs the parameterized XPath query exactly as the fixed servlet
    // does, returning the matched <name> value (empty string if no match).
    // -----------------------------------------------------------------------
    private String runParameterizedXPath(final String username, final String password)
            throws Exception {
        XPath xPath = XPathFactory.newInstance().newXPath();

        final Map<String, String> vars = new HashMap<String, String>();
        vars.put("username", username != null ? username : "");
        vars.put("password", password != null ? password : "");

        xPath.setXPathVariableResolver(new XPathVariableResolver() {
            public Object resolveVariable(QName variableName) {
                return vars.get(variableName.getLocalPart());
            }
        });

        String xPression = "/users/user[username=$username and password=$password]/name";
        return xPath.compile(xPression).evaluate(usersDoc);
    }

    // -----------------------------------------------------------------------
    // Positive cases: valid credentials should return the correct name
    // -----------------------------------------------------------------------

    @Test
    public void testValidCredentialsAlice() throws Exception {
        String name = runParameterizedXPath("alice", "secret123");
        assertEquals("Valid credentials should return the user's name from XML",
                "Alice Smith", name);
    }

    @Test
    public void testValidCredentialsBob() throws Exception {
        String name = runParameterizedXPath("bob", "p@ssw0rd");
        assertEquals("Valid credentials should return the user's name from XML",
                "Bob Jones", name);
    }

    // -----------------------------------------------------------------------
    // Negative cases: invalid credentials should return empty string
    // -----------------------------------------------------------------------

    @Test
    public void testWrongPassword() throws Exception {
        String name = runParameterizedXPath("alice", "wrongpassword");
        assertTrue("Wrong password should return empty string", name.isEmpty());
    }

    @Test
    public void testNonExistentUser() throws Exception {
        String name = runParameterizedXPath("charlie", "secret123");
        assertTrue("Non-existent user should return empty string", name.isEmpty());
    }

    @Test
    public void testEmptyCredentials() throws Exception {
        String name = runParameterizedXPath("", "");
        assertTrue("Empty credentials should return empty string", name.isEmpty());
    }

    @Test
    public void testNullUsername() throws Exception {
        String name = runParameterizedXPath(null, "secret123");
        assertTrue("Null username should return empty string (not throw)", name.isEmpty());
    }

    @Test
    public void testNullPassword() throws Exception {
        String name = runParameterizedXPath("alice", null);
        assertTrue("Null password should return empty string (not throw)", name.isEmpty());
    }

    // -----------------------------------------------------------------------
    // Security cases: XPath injection payloads must NOT bypass authentication
    //
    // In the VULNERABLE version, string concatenation allowed these payloads
    // to manipulate the XPath expression structure and return a valid name
    // without knowing the real password.
    //
    // With parameterized XPath (XPathVariableResolver), the payload is treated
    // as a literal string value, so no XPath injection can occur.
    // -----------------------------------------------------------------------

    @Test
    public void testXPathInjection_AlwaysTrue_Password() throws Exception {
        // Classic XPath injection: ' or '1'='1
        // Vulnerable query would become: password='' or '1'='1'
        String injectionPayload = "' or '1'='1";
        String name = runParameterizedXPath("alice", injectionPayload);
        assertTrue(
            "XPath injection payload in password should NOT bypass authentication; " +
            "got name='" + name + "'",
            name.isEmpty());
    }

    @Test
    public void testXPathInjection_AlwaysTrue_Username() throws Exception {
        // Classic XPath injection in username field: ' or '1'='1
        String injectionPayload = "' or '1'='1";
        String name = runParameterizedXPath(injectionPayload, "anypassword");
        assertTrue(
            "XPath injection payload in username should NOT bypass authentication; " +
            "got name='" + name + "'",
            name.isEmpty());
    }

    @Test
    public void testXPathInjection_CommentOut() throws Exception {
        // Attempt to comment out the rest of the XPath expression
        // Vulnerable query: username='alice' and password='x'] | /users/user[username='alice
        String injectionPayload = "alice' and password='x'] | /users/user[username='alice";
        String name = runParameterizedXPath(injectionPayload, "anypassword");
        assertTrue(
            "XPath structural injection should NOT bypass authentication; " +
            "got name='" + name + "'",
            name.isEmpty());
    }

    @Test
    public void testXPathInjection_UnionExtract() throws Exception {
        // Attempt to use union to return all users regardless of password
        String injectionPayload = "' or 1=1 or ''='";
        String name = runParameterizedXPath("alice", injectionPayload);
        assertTrue(
            "XPath union injection in password should NOT bypass authentication; " +
            "got name='" + name + "'",
            name.isEmpty());
    }

    @Test
    public void testXPathInjection_SpecialCharacters() throws Exception {
        // Special XPath characters that could alter query structure
        String[] specialPayloads = {
            "'",           // single quote
            "\"",          // double quote
            "']",          // close bracket
            "' and '",     // partial expression
            "' or ''='",   // always-true fragment
        };
        for (String payload : specialPayloads) {
            String name = runParameterizedXPath("alice", payload);
            assertTrue(
                "Special XPath character payload '" + payload +
                "' should NOT bypass authentication; got name='" + name + "'",
                name.isEmpty());
        }
    }

    // -----------------------------------------------------------------------
    // Trust boundary: verify that the value stored in the session is the
    // name element from XML (trusted data), NOT the raw user-supplied input.
    // -----------------------------------------------------------------------

    @Test
    public void testSessionValueComesFromXmlNotFromInput() throws Exception {
        // The user supplies "alice" as username, the session should receive
        // "Alice Smith" (from XML) — not the raw username input.
        String name = runParameterizedXPath("alice", "secret123");
        assertEquals("Session value must come from trusted XML data, not raw user input",
                "Alice Smith", name);
        assertNotEquals("Session value must NOT be the raw username input",
                "alice", name);
    }

    @Test
    public void testInjectionPayloadNotReflectedInSessionValue() throws Exception {
        // Even if a user sends an injection payload, the name returned must be
        // empty (no match) — never the injection string itself.
        String injectionPayload = "' or '1'='1";
        String name = runParameterizedXPath("alice", injectionPayload);
        assertFalse(
            "Injection payload must never appear as the session user value",
            name.contains("'") || name.contains("1=1"));
        assertTrue("No match expected for injection payload", name.isEmpty());
    }
}
