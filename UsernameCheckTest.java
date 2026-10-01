package org.cysecurity.cspf.jvl.controller;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Tests for UsernameCheck servlet.
 *
 * Regression tests for CWE-346 / Missing HSTS Header vulnerability.
 * Verifies that every response from processRequest() includes the
 * Strict-Transport-Security header with a max-age of at least one year
 * and the includeSubDomains directive.
 */
@RunWith(MockitoJUnitRunner.class)
public class UsernameCheckTest {

    private UsernameCheck servlet;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private ServletContext servletContext;

    private StringWriter responseBody;
    private PrintWriter printWriter;

    /** Required max-age value (one year in seconds) for HSTS compliance. */
    private static final int HSTS_MIN_MAX_AGE_SECONDS = 31536000;

    @Before
    public void setUp() throws Exception {
        responseBody = new StringWriter();
        printWriter = new PrintWriter(responseBody);

        when(response.getWriter()).thenReturn(printWriter);
        // Return a non-existent path so DBConnect.connect() returns null/throws,
        // exercising the catch-branch while still triggering the HSTS header set
        // before the writer is obtained.
        when(servletContext.getRealPath("/WEB-INF/config.properties"))
                .thenReturn("/nonexistent/config.properties");

        // Provide a minimal username parameter so the servlet doesn't NPE before
        // the HSTS header line.
        when(request.getParameter("username")).thenReturn("testuser");

        // Create the servlet and inject the mocked ServletContext.
        servlet = new UsernameCheck() {
            @Override
            public ServletContext getServletContext() {
                return servletContext;
            }
        };
    }

    // -----------------------------------------------------------------------
    // HSTS header presence and correctness tests
    // -----------------------------------------------------------------------

    /**
     * The response MUST include the Strict-Transport-Security header.
     * Absence of this header is the CWE-346 vulnerability being fixed.
     */
    @Test
    public void testHstsHeaderIsPresent() throws Exception {
        // Capture the header name/value pairs set on the response
        ArgumentCaptor<String> headerNameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> headerValueCaptor = ArgumentCaptor.forClass(String.class);

        servlet.doGet(request, response);

        verify(response, atLeastOnce()).setHeader(
                headerNameCaptor.capture(), headerValueCaptor.capture());

        boolean hstsFound = false;
        for (String name : headerNameCaptor.getAllValues()) {
            if ("Strict-Transport-Security".equalsIgnoreCase(name)) {
                hstsFound = true;
                break;
            }
        }
        assertTrue(
                "Response must include the Strict-Transport-Security header to prevent MitM attacks",
                hstsFound);
    }

    /**
     * The HSTS header value MUST contain max-age=31536000 (one year).
     */
    @Test
    public void testHstsHeaderMaxAge() throws Exception {
        ArgumentCaptor<String> headerNameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> headerValueCaptor = ArgumentCaptor.forClass(String.class);

        servlet.doGet(request, response);

        verify(response, atLeastOnce()).setHeader(
                headerNameCaptor.capture(), headerValueCaptor.capture());

        String hstsValue = null;
        java.util.List<String> names = headerNameCaptor.getAllValues();
        java.util.List<String> values = headerValueCaptor.getAllValues();
        for (int i = 0; i < names.size(); i++) {
            if ("Strict-Transport-Security".equalsIgnoreCase(names.get(i))) {
                hstsValue = values.get(i);
                break;
            }
        }

        assertNotNull("Strict-Transport-Security header must be set", hstsValue);

        // Extract max-age value
        int maxAge = extractMaxAge(hstsValue);
        assertTrue(
                "HSTS max-age must be at least " + HSTS_MIN_MAX_AGE_SECONDS
                        + " seconds (one year). Actual value: " + maxAge,
                maxAge >= HSTS_MIN_MAX_AGE_SECONDS);
    }

    /**
     * The HSTS header MUST include the includeSubDomains directive to maximise coverage.
     */
    @Test
    public void testHstsHeaderIncludesSubDomains() throws Exception {
        ArgumentCaptor<String> headerNameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> headerValueCaptor = ArgumentCaptor.forClass(String.class);

        servlet.doGet(request, response);

        verify(response, atLeastOnce()).setHeader(
                headerNameCaptor.capture(), headerValueCaptor.capture());

        String hstsValue = null;
        java.util.List<String> names = headerNameCaptor.getAllValues();
        java.util.List<String> values = headerValueCaptor.getAllValues();
        for (int i = 0; i < names.size(); i++) {
            if ("Strict-Transport-Security".equalsIgnoreCase(names.get(i))) {
                hstsValue = values.get(i);
                break;
            }
        }

        assertNotNull("Strict-Transport-Security header must be set", hstsValue);
        assertTrue(
                "HSTS header must contain 'includeSubDomains' directive. Actual value: " + hstsValue,
                hstsValue.contains("includeSubDomains"));
    }

    /**
     * The HSTS header must be set even when an exception occurs (e.g. DB not available),
     * because the header is written before the try/catch block.
     */
    @Test
    public void testHstsHeaderPresentOnErrorPath() throws Exception {
        // Simulate a bad username param that causes an NPE inside the try block
        when(request.getParameter("username")).thenReturn(null);

        ArgumentCaptor<String> headerNameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> headerValueCaptor = ArgumentCaptor.forClass(String.class);

        // The servlet should not throw; the exception is caught internally
        servlet.doPost(request, response);

        verify(response, atLeastOnce()).setHeader(
                headerNameCaptor.capture(), headerValueCaptor.capture());

        boolean hstsFound = false;
        for (String name : headerNameCaptor.getAllValues()) {
            if ("Strict-Transport-Security".equalsIgnoreCase(name)) {
                hstsFound = true;
                break;
            }
        }
        assertTrue(
                "HSTS header must be set even when request processing encounters an exception",
                hstsFound);
    }

    /**
     * doPost() must also set the HSTS header (it delegates to processRequest).
     */
    @Test
    public void testHstsHeaderPresentOnPostRequest() throws Exception {
        ArgumentCaptor<String> headerNameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> headerValueCaptor = ArgumentCaptor.forClass(String.class);

        servlet.doPost(request, response);

        verify(response, atLeastOnce()).setHeader(
                headerNameCaptor.capture(), headerValueCaptor.capture());

        boolean hstsFound = false;
        for (String name : headerNameCaptor.getAllValues()) {
            if ("Strict-Transport-Security".equalsIgnoreCase(name)) {
                hstsFound = true;
                break;
            }
        }
        assertTrue(
                "HSTS header must be present on POST responses as well as GET",
                hstsFound);
    }

    /**
     * The response Content-Type must remain application/json (functionality preserved).
     */
    @Test
    public void testContentTypeIsStillJson() throws Exception {
        servlet.doGet(request, response);
        verify(response).setContentType("application/json");
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    /**
     * Parse the max-age value from an HSTS header string such as
     * "max-age=31536000; includeSubDomains".
     *
     * @return the parsed max-age in seconds, or -1 if not found / unparseable
     */
    private static int extractMaxAge(String hstsValue) {
        if (hstsValue == null) {
            return -1;
        }
        for (String directive : hstsValue.split(";")) {
            String trimmed = directive.trim();
            if (trimmed.toLowerCase().startsWith("max-age=")) {
                try {
                    return Integer.parseInt(trimmed.substring("max-age=".length()).trim());
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        }
        return -1;
    }
}
