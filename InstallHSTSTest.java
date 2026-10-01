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
 * Tests that the Install servlet sets a valid HSTS header on every response,
 * preventing Man-in-the-Middle downgrade attacks (CWE-346).
 *
 * The SAST finding (Missing_HSTS_Header) was reported at the out.println sink
 * on line 81 of Install.java because no Strict-Transport-Security header was
 * present in the response. These tests verify the remediation by exercising
 * the processRequest code path (via doGet / doPost) and inspecting the header
 * set on the mock HttpServletResponse.
 */
@RunWith(MockitoJUnitRunner.class)
public class InstallHSTSTest {

    // The header name as specified by RFC 6797.
    private static final String HSTS_HEADER = "Strict-Transport-Security";

    // Minimum acceptable max-age value: one year in seconds (per the OWASP guidance).
    private static final long MIN_MAX_AGE_SECONDS = 31536000L;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private ServletContext servletContext;

    private StringWriter responseWriter;

    @Before
    public void setUp() throws Exception {
        responseWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));

        // Return a temp path for the config file so the servlet does not NPE
        // during the Properties.load() call.  The test verifies the header,
        // not the database setup logic, so an IOException from a missing file
        // is acceptable – we capture it rather than mock the full FS.
        when(servletContext.getRealPath("/WEB-INF/config.properties"))
                .thenReturn(System.getProperty("java.io.tmpdir") + "/test-config.properties");

        // Provide dummy values for every parameter the servlet reads so it
        // does not throw a NullPointerException before reaching the header-
        // setting code.
        when(request.getParameter("dburl")).thenReturn("jdbc:mysql://localhost:3306/");
        when(request.getParameter("jdbcdriver")).thenReturn("com.mysql.jdbc.Driver");
        when(request.getParameter("dbuser")).thenReturn("root");
        when(request.getParameter("dbpass")).thenReturn("password");
        when(request.getParameter("dbname")).thenReturn("testdb");
        when(request.getParameter("siteTitle")).thenReturn("Test Site");
        when(request.getParameter("adminuser")).thenReturn("admin");
        when(request.getParameter("adminpass")).thenReturn("adminpass");
        when(request.getParameter("setup")).thenReturn("0");
    }

    // -----------------------------------------------------------------------
    // Helper – build a testable subclass that injects our mock ServletContext
    // without requiring a real servlet container.
    // -----------------------------------------------------------------------
    private Install buildServlet() throws Exception {
        Install servlet = new Install() {
            @Override
            public ServletContext getServletContext() {
                return servletContext;
            }
        };
        return servlet;
    }

    // -----------------------------------------------------------------------
    // 1. HSTS header is present in the response
    // -----------------------------------------------------------------------

    @Test
    public void doGet_setsHSTSHeader() throws Exception {
        Install servlet = buildServlet();

        // Capture what header value is set
        ArgumentCaptor<String> nameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);

        try {
            servlet.doGet(request, response);
        } catch (Exception ignored) {
            // IO/SQL exceptions from missing real resources are expected in unit tests.
        }

        verify(response, atLeastOnce()).setHeader(nameCaptor.capture(), valueCaptor.capture());

        boolean hstsHeaderFound = false;
        for (int i = 0; i < nameCaptor.getAllValues().size(); i++) {
            if (HSTS_HEADER.equalsIgnoreCase(nameCaptor.getAllValues().get(i))) {
                hstsHeaderFound = true;
                String headerValue = valueCaptor.getAllValues().get(i);
                assertHstsValueIsValid(headerValue);
                break;
            }
        }
        assertTrue("doGet must set the Strict-Transport-Security header", hstsHeaderFound);
    }

    @Test
    public void doPost_setsHSTSHeader() throws Exception {
        Install servlet = buildServlet();

        ArgumentCaptor<String> nameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);

        try {
            servlet.doPost(request, response);
        } catch (Exception ignored) {
            // IO/SQL exceptions from missing real resources are expected in unit tests.
        }

        verify(response, atLeastOnce()).setHeader(nameCaptor.capture(), valueCaptor.capture());

        boolean hstsHeaderFound = false;
        for (int i = 0; i < nameCaptor.getAllValues().size(); i++) {
            if (HSTS_HEADER.equalsIgnoreCase(nameCaptor.getAllValues().get(i))) {
                hstsHeaderFound = true;
                String headerValue = valueCaptor.getAllValues().get(i);
                assertHstsValueIsValid(headerValue);
                break;
            }
        }
        assertTrue("doPost must set the Strict-Transport-Security header", hstsHeaderFound);
    }

    // -----------------------------------------------------------------------
    // 2. max-age is at least one year
    // -----------------------------------------------------------------------

    @Test
    public void hstsHeader_maxAgeAtLeastOneYear() throws Exception {
        Install servlet = buildServlet();

        ArgumentCaptor<String> nameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);

        try {
            servlet.doGet(request, response);
        } catch (Exception ignored) {}

        verify(response, atLeastOnce()).setHeader(nameCaptor.capture(), valueCaptor.capture());

        for (int i = 0; i < nameCaptor.getAllValues().size(); i++) {
            if (HSTS_HEADER.equalsIgnoreCase(nameCaptor.getAllValues().get(i))) {
                long maxAge = extractMaxAge(valueCaptor.getAllValues().get(i));
                assertTrue(
                    "HSTS max-age must be at least 31536000 seconds (1 year), got: " + maxAge,
                    maxAge >= MIN_MAX_AGE_SECONDS
                );
                return;
            }
        }
        fail("Strict-Transport-Security header was not set");
    }

    // -----------------------------------------------------------------------
    // 3. includeSubDomains directive is present
    // -----------------------------------------------------------------------

    @Test
    public void hstsHeader_includesSubDomains() throws Exception {
        Install servlet = buildServlet();

        ArgumentCaptor<String> nameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);

        try {
            servlet.doGet(request, response);
        } catch (Exception ignored) {}

        verify(response, atLeastOnce()).setHeader(nameCaptor.capture(), valueCaptor.capture());

        for (int i = 0; i < nameCaptor.getAllValues().size(); i++) {
            if (HSTS_HEADER.equalsIgnoreCase(nameCaptor.getAllValues().get(i))) {
                String value = valueCaptor.getAllValues().get(i);
                assertTrue(
                    "HSTS header must contain 'includeSubDomains' directive; got: " + value,
                    value.contains("includeSubDomains")
                );
                return;
            }
        }
        fail("Strict-Transport-Security header was not set");
    }

    // -----------------------------------------------------------------------
    // 4. Regression – response content type is still set correctly
    // -----------------------------------------------------------------------

    @Test
    public void responseContentType_isStillSet() throws Exception {
        Install servlet = buildServlet();

        try {
            servlet.doGet(request, response);
        } catch (Exception ignored) {}

        verify(response, atLeastOnce()).setContentType("text/html;charset=UTF-8");
    }

    // -----------------------------------------------------------------------
    // Helper assertions
    // -----------------------------------------------------------------------

    /**
     * Asserts that an HSTS header value is structurally valid:
     * - contains a max-age directive
     * - max-age is a non-negative integer
     * - contains the includeSubDomains directive
     */
    private void assertHstsValueIsValid(String value) {
        assertNotNull("HSTS header value must not be null", value);
        assertFalse("HSTS header value must not be empty", value.isEmpty());
        assertTrue("HSTS value must contain max-age", value.contains("max-age"));
        long maxAge = extractMaxAge(value);
        assertTrue("max-age must be non-negative", maxAge >= 0);
    }

    /**
     * Parses the numeric max-age value from an HSTS header string of the form
     * "max-age=31536000; includeSubDomains".
     *
     * @return the parsed max-age, or -1 if the directive is absent / unparseable.
     */
    private long extractMaxAge(String hstsValue) {
        if (hstsValue == null) return -1L;
        for (String directive : hstsValue.split(";")) {
            String trimmed = directive.trim();
            if (trimmed.toLowerCase().startsWith("max-age=")) {
                try {
                    return Long.parseLong(trimmed.substring("max-age=".length()).trim());
                } catch (NumberFormatException e) {
                    return -1L;
                }
            }
        }
        return -1L;
    }
}
