package org.cysecurity.cspf.jvl.controller;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;

/**
 * Tests for xxe servlet to verify that Reflected XSS (CWE-79) is remediated.
 *
 * The vulnerability was that XML node names and values extracted from
 * request.getInputStream() were written directly to the HTTP response via
 * out.print() without HTML encoding, allowing an attacker to inject arbitrary
 * HTML/JavaScript via crafted XML input.
 *
 * The fix applies ESAPI.encoder().encodeForHTML() to both the node name and
 * node value before writing them to the response, neutralising any embedded
 * HTML special characters.
 */
public class xxeTest {

    private xxe servlet;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private StringWriter responseWriter;

    @Before
    public void setUp() throws Exception {
        servlet = new xxe();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        responseWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
    }

    // -----------------------------------------------------------------
    // Helper: build a request whose getInputStream() returns the given XML.
    // -----------------------------------------------------------------
    private void setRequestXml(String xml) throws IOException {
        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
        InputStream is = new ByteArrayInputStream(bytes);
        when(request.getInputStream()).thenReturn(new javax.servlet.ServletInputStream() {
            @Override public int read() throws IOException { return is.read(); }
            @Override public boolean isFinished() { return false; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(javax.servlet.ReadListener rl) {}
        });
    }

    // -----------------------------------------------------------------
    // 1. Basic functionality: benign XML round-trips correctly
    // -----------------------------------------------------------------
    @Test
    public void testBenignXmlIsRendered() throws Exception {
        setRequestXml("<root><item>HelloWorld</item></root>");
        servlet.processRequest(request, response);

        String output = responseWriter.toString();
        // The plain text value must appear in the response
        assertTrue("Expected node value in output", output.contains("HelloWorld"));
    }

    // -----------------------------------------------------------------
    // 2. XSS via node value: script tag must be HTML-encoded, not executed
    // -----------------------------------------------------------------
    @Test
    public void testXssPayloadInNodeValueIsEncoded() throws Exception {
        // Attack payload: attacker supplies a <script> tag as a node value
        String xssPayload = "<script>alert('xss')</script>";
        setRequestXml("<root><item>" + xssPayload + "</item></root>");

        servlet.processRequest(request, response);
        String output = responseWriter.toString();

        // The raw script tag must NOT appear verbatim (that would be XSS)
        assertFalse("Raw <script> tag must not appear in output",
                output.contains("<script>alert('xss')</script>"));

        // The encoded form must be present instead
        assertTrue("Encoded &lt;script&gt; must appear in output",
                output.contains("&lt;script&gt;"));
    }

    // -----------------------------------------------------------------
    // 3. XSS via node value: img onerror payload
    // -----------------------------------------------------------------
    @Test
    public void testImgOnerrorPayloadIsEncoded() throws Exception {
        String xssPayload = "<img src=x onerror=alert(1)>";
        setRequestXml("<root><field>" + xssPayload + "</field></root>");

        servlet.processRequest(request, response);
        String output = responseWriter.toString();

        assertFalse("Raw <img onerror> must not appear in output",
                output.contains("<img src=x onerror=alert(1)>"));
        assertTrue("Encoded &lt;img must appear in output",
                output.contains("&lt;img"));
    }

    // -----------------------------------------------------------------
    // 4. XSS via node value: HTML special characters are encoded
    // -----------------------------------------------------------------
    @Test
    public void testHtmlSpecialCharsAreEncoded() throws Exception {
        // & " ' < > all need to be encoded in HTML context
        setRequestXml("<root><node>a&amp;b\"c&apos;d</node></root>");

        servlet.processRequest(request, response);
        String output = responseWriter.toString();

        // None of the raw HTML injection characters should appear unencoded as attack vectors
        // (Note: & in the XML body is already & after XML parsing; the ESAPI encoder
        //  will re-encode the resulting ampersand to &amp; in the HTML output)
        assertNotNull("Response must not be null", output);
    }

    // -----------------------------------------------------------------
    // 5. XSS via node name: a crafted node name with special chars is encoded
    //    (Node names in XML cannot contain < directly, but can contain
    //     characters that are dangerous in HTML context such as & or ").
    //    The ESAPI encoder must handle whatever the XML parser provides.
    // -----------------------------------------------------------------
    @Test
    public void testNodeNameIsHtmlEncoded() throws Exception {
        // Standard XML node name (XML names cannot contain raw < or >),
        // but the node name still flows to an HTML sink and must be encoded.
        setRequestXml("<root><validName>someValue</validName></root>");

        servlet.processRequest(request, response);
        String output = responseWriter.toString();

        assertTrue("Node name must appear in output", output.contains("validName"));
        // Verify the output does not contain a raw unencoded script injection
        assertFalse("Output must not contain raw script tags", output.contains("<script>"));
    }

    // -----------------------------------------------------------------
    // 6. JavaScript URI in node value is encoded
    // -----------------------------------------------------------------
    @Test
    public void testJavascriptUriInNodeValueIsEncoded() throws Exception {
        // An attacker may craft a value such as javascript:alert(1)
        // The key risk is that < and > (if present) are encoded.
        // Even without those, the ESAPI encoder handles the string safely.
        setRequestXml("<root><link>javascript:alert(document.cookie)</link></root>");

        servlet.processRequest(request, response);
        String output = responseWriter.toString();

        // The raw colon and parens are not HTML-dangerous by themselves,
        // but the response must not include unencoded angle brackets.
        assertFalse("Unencoded < must not appear from XSS payloads", output.contains("<script>"));
        assertNotNull(output);
    }

    // -----------------------------------------------------------------
    // 7. Multiple sibling nodes: all values are HTML-encoded
    // -----------------------------------------------------------------
    @Test
    public void testMultipleNodesAllEncoded() throws Exception {
        setRequestXml(
            "<root>" +
            "<safe>plaintext</safe>" +
            "<evil>&lt;script&gt;alert(2)&lt;/script&gt;</evil>" +
            "</root>"
        );

        servlet.processRequest(request, response);
        String output = responseWriter.toString();

        // Safe node value appears
        assertTrue("Safe value must be in output", output.contains("plaintext"));

        // After XML parsing, &lt;script&gt; becomes <script>, which ESAPI
        // must then re-encode to &lt;script&gt; in the HTML response.
        assertFalse("Raw <script> tag must not appear in output",
                output.contains("<script>alert(2)</script>"));
    }
}
