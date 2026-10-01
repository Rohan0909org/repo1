package org.cysecurity.cspf.jvl.controller;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Tests for CSRF protection in the Install servlet (CWE-352).
 *
 * The synchronizer token pattern requires:
 *  1. A CSRF token is generated per-session and embedded in every form.
 *  2. Each state-changing POST must carry the token back in the request body.
 *  3. The server rejects any request whose token is absent, null, or mismatched.
 */
public class InstallCsrfTest {

    private Install servlet;
    private HttpServletRequest  request;
    private HttpServletResponse response;
    private HttpSession         session;

    @Before
    public void setUp() {
        servlet  = new Install();
        request  = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        session  = mock(HttpSession.class);

        when(request.getSession()).thenReturn(session);
    }

    // -----------------------------------------------------------------------
    // CSRF token generation
    // -----------------------------------------------------------------------

    /**
     * generateCsrfToken() must produce a non-null, non-empty string and
     * store it under the "csrfToken" session attribute.
     */
    @Test
    public void generateCsrfToken_storesTokenInSession() {
        String token = Install.generateCsrfToken(session);

        assertNotNull("Token must not be null", token);
        assertFalse("Token must not be empty", token.isEmpty());
        verify(session).setAttribute("csrfToken", token);
    }

    /**
     * Each call to generateCsrfToken() must return a different value so that
     * a stolen token from a previous session cannot be reused.
     */
    @Test
    public void generateCsrfToken_isUniquePerCall() {
        HttpSession s1 = mock(HttpSession.class);
        HttpSession s2 = mock(HttpSession.class);

        String t1 = Install.generateCsrfToken(s1);
        String t2 = Install.generateCsrfToken(s2);

        assertNotEquals("Tokens for different sessions must differ", t1, t2);
    }

    /**
     * Token must be at least 32 characters (URL-safe Base64 of 32 bytes = 43
     * characters without padding) so it carries sufficient entropy.
     */
    @Test
    public void generateCsrfToken_hasSufficientLength() {
        HttpSession s = mock(HttpSession.class);
        String token = Install.generateCsrfToken(s);
        // Base64url(32 bytes) without padding = 43 characters
        assertTrue("Token must have at least 43 characters, got: " + token.length(),
                token.length() >= 43);
    }

    // -----------------------------------------------------------------------
    // doGet embeds a CSRF token in the form
    // -----------------------------------------------------------------------

    /**
     * A GET request must issue a fresh CSRF token, store it in the session,
     * and embed it as a hidden field in the returned HTML form.
     */
    @Test
    public void doGet_embedsCsrfTokenInForm() throws ServletException, IOException {
        StringWriter sw = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(sw));

        servlet.doGet(request, response);

        String html = sw.toString();
        assertTrue("Response HTML must contain a hidden csrfToken input",
                html.contains("name=\"csrfToken\""));

        // The session must have had a token set on it
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(session).setAttribute(eq("csrfToken"), captor.capture());
        String storedToken = captor.getValue();

        assertTrue("The token embedded in the form must appear in the HTML",
                html.contains("value=\"" + storedToken + "\""));
    }

    // -----------------------------------------------------------------------
    // doPost / processRequest: CSRF enforcement
    // -----------------------------------------------------------------------

    /**
     * A POST with no csrfToken parameter must be rejected with HTTP 403.
     * The state-changing logic (DB setup) must never be reached.
     */
    @Test
    public void processRequest_rejectsPostWithNoCsrfToken()
            throws ServletException, IOException {
        // Session has a valid token; request provides none
        when(session.getAttribute("csrfToken")).thenReturn("valid-session-token");
        when(request.getParameter("csrfToken")).thenReturn(null);

        servlet.doPost(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
        // Ensure the processing path was not entered (no DB params read)
        verify(request, never()).getParameter("dbuser");
    }

    /**
     * A POST with an empty csrfToken parameter must be rejected with HTTP 403.
     */
    @Test
    public void processRequest_rejectsPostWithEmptyCsrfToken()
            throws ServletException, IOException {
        when(session.getAttribute("csrfToken")).thenReturn("valid-session-token");
        when(request.getParameter("csrfToken")).thenReturn("");

        servlet.doPost(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
        verify(request, never()).getParameter("dbuser");
    }

    /**
     * A POST where the form token does not match the session token (typical
     * CSRF attempt) must be rejected with HTTP 403.
     */
    @Test
    public void processRequest_rejectsPostWithMismatchedCsrfToken()
            throws ServletException, IOException {
        when(session.getAttribute("csrfToken")).thenReturn("correct-token");
        when(request.getParameter("csrfToken")).thenReturn("attacker-injected-token");

        servlet.doPost(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
        verify(request, never()).getParameter("dbuser");
    }

    /**
     * A POST with no session token (session freshly created, token never
     * generated) must be rejected even if the request carries a token.
     */
    @Test
    public void processRequest_rejectsPostWhenSessionHasNoToken()
            throws ServletException, IOException {
        when(session.getAttribute("csrfToken")).thenReturn(null);
        when(request.getParameter("csrfToken")).thenReturn("some-token");

        servlet.doPost(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
        verify(request, never()).getParameter("dbuser");
    }

    /**
     * A POST that supplies the correct token must pass the CSRF guard and
     * attempt to read the database parameters (the taint source identified
     * in the SAST finding: request.getParameter("dbuser") at line 56 of
     * the original file / line 87 of the patched file).
     *
     * We verify only that the CSRF check is passed; the DB setup itself is
     * not exercised here because it requires a live JDBC environment.
     */
    @Test
    public void processRequest_allowsPostWithValidCsrfToken()
            throws ServletException, IOException {
        final String TOKEN = "correct-session-token";
        when(session.getAttribute("csrfToken")).thenReturn(TOKEN);
        when(request.getParameter("csrfToken")).thenReturn(TOKEN);

        // The method proceeds past the CSRF check and reaches getParameter("dbuser")
        // (the taint source). Verify the CSRF check does NOT block this request.
        // We expect no 403 error to be sent.
        servlet.doPost(request, response);

        verify(response, never()).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
        // The servlet reads "dbuser" — the source identified in the SAST finding
        verify(request, atLeastOnce()).getParameter("dbuser");
    }

    // -----------------------------------------------------------------------
    // Token entropy / uniqueness stress test
    // -----------------------------------------------------------------------

    /**
     * Generate a large number of tokens and assert there are no collisions,
     * confirming the SecureRandom source provides adequate entropy.
     */
    @Test
    public void generateCsrfToken_noCollisionsUnderStress() {
        int count = 200;
        java.util.Set<String> tokens = new java.util.HashSet<>();
        for (int i = 0; i < count; i++) {
            HttpSession s = mock(HttpSession.class);
            tokens.add(Install.generateCsrfToken(s));
        }
        assertEquals("All " + count + " generated tokens must be unique", count, tokens.size());
    }
}
