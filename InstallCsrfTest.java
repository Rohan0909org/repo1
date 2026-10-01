package org.cysecurity.cspf.jvl.controller;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Tests for CSRF protection in Install servlet.
 *
 * Verifies that:
 * 1. A valid CSRF token (session matches request) is accepted.
 * 2. A missing CSRF token is rejected.
 * 3. A mismatched CSRF token is rejected.
 * 4. A null session is rejected.
 * 5. A token present only in the request (no session) is rejected.
 * 6. An empty-string token is rejected.
 * 7. processRequest returns 403 when CSRF token is absent (POST).
 * 8. processRequest proceeds past CSRF check when token is valid (POST).
 * 9. generateCsrfToken produces a non-null, non-empty token stored in the session.
 * 10. Successive calls to generateCsrfToken produce different tokens (uniqueness).
 */
public class InstallCsrfTest {

    /**
     * A testable subclass of Install that overrides methods requiring
     * a live ServletContext or database, allowing us to test CSRF logic
     * in isolation.
     */
    private static class TestableInstall extends Install {
        // Expose processRequest for direct testing without a real container.
        public void testProcessRequest(HttpServletRequest req, HttpServletResponse resp)
                throws Exception {
            processRequest(req, resp);
        }
    }

    private TestableInstall servlet;

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpServletResponse mockResponse;

    @Mock
    private HttpSession mockSession;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        servlet = new TestableInstall();
    }

    // -------------------------------------------------------------------------
    // Tests for isValidCsrfToken()
    // -------------------------------------------------------------------------

    /**
     * A matching token in both session and request should be accepted.
     */
    @Test
    public void testValidCsrfToken_matchingToken_returnsTrue() {
        String token = "validToken123";
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("csrfToken")).thenReturn(token);
        when(mockRequest.getParameter("csrfToken")).thenReturn(token);

        assertTrue("Matching CSRF token must be accepted", servlet.isValidCsrfToken(mockRequest));
    }

    /**
     * No session at all — must be rejected.
     */
    @Test
    public void testValidCsrfToken_noSession_returnsFalse() {
        when(mockRequest.getSession(false)).thenReturn(null);

        assertFalse("Request with no session must be rejected", servlet.isValidCsrfToken(mockRequest));
    }

    /**
     * Session exists but has no stored token — must be rejected.
     */
    @Test
    public void testValidCsrfToken_noSessionToken_returnsFalse() {
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("csrfToken")).thenReturn(null);
        when(mockRequest.getParameter("csrfToken")).thenReturn("someToken");

        assertFalse("Request without a session CSRF token must be rejected",
                servlet.isValidCsrfToken(mockRequest));
    }

    /**
     * Token submitted in request is null — must be rejected.
     */
    @Test
    public void testValidCsrfToken_noRequestToken_returnsFalse() {
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("csrfToken")).thenReturn("sessionToken");
        when(mockRequest.getParameter("csrfToken")).thenReturn(null);

        assertFalse("Request without a submitted CSRF token must be rejected",
                servlet.isValidCsrfToken(mockRequest));
    }

    /**
     * Token in request differs from session token — must be rejected.
     * This is the core CSRF attack scenario: the attacker submits a wrong/forged token.
     */
    @Test
    public void testValidCsrfToken_mismatchedToken_returnsFalse() {
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("csrfToken")).thenReturn("realSessionToken");
        when(mockRequest.getParameter("csrfToken")).thenReturn("attackerForgedToken");

        assertFalse("Mismatched CSRF token (attacker forged) must be rejected",
                servlet.isValidCsrfToken(mockRequest));
    }

    /**
     * Empty-string token must not be treated as valid.
     */
    @Test
    public void testValidCsrfToken_emptyStringToken_returnsFalse() {
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("csrfToken")).thenReturn("sessionToken");
        when(mockRequest.getParameter("csrfToken")).thenReturn("");

        assertFalse("Empty CSRF token must be rejected", servlet.isValidCsrfToken(mockRequest));
    }

    /**
     * Empty session token with empty request token must not be treated as valid.
     */
    @Test
    public void testValidCsrfToken_bothEmptyTokens_returnsFalse() {
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        // A null session attribute is also an absent token
        when(mockSession.getAttribute("csrfToken")).thenReturn(null);
        when(mockRequest.getParameter("csrfToken")).thenReturn("");

        assertFalse("Null session token with empty request token must be rejected",
                servlet.isValidCsrfToken(mockRequest));
    }

    // -------------------------------------------------------------------------
    // Tests for generateCsrfToken()
    // -------------------------------------------------------------------------

    /**
     * generateCsrfToken must return a non-null, non-empty token.
     */
    @Test
    public void testGenerateCsrfToken_returnsNonEmptyToken() {
        String token = servlet.generateCsrfToken(mockSession);

        assertNotNull("Generated CSRF token must not be null", token);
        assertFalse("Generated CSRF token must not be empty", token.isEmpty());
    }

    /**
     * generateCsrfToken must store the token in the session under "csrfToken".
     */
    @Test
    public void testGenerateCsrfToken_storesTokenInSession() {
        String token = servlet.generateCsrfToken(mockSession);

        verify(mockSession, times(1)).setAttribute("csrfToken", token);
    }

    /**
     * Successive calls to generateCsrfToken must produce different tokens
     * (cryptographic uniqueness requirement).
     */
    @Test
    public void testGenerateCsrfToken_uniqueAcrossCalls() {
        String token1 = servlet.generateCsrfToken(mockSession);
        String token2 = servlet.generateCsrfToken(mockSession);

        assertNotEquals("Successive CSRF tokens must differ", token1, token2);
    }

    // -------------------------------------------------------------------------
    // Integration-level tests for processRequest()
    // -------------------------------------------------------------------------

    /**
     * A POST with no CSRF token must result in a 403 Forbidden response,
     * and the state-altering operation must NOT be reached.
     */
    @Test
    public void testProcessRequest_postWithoutCsrfToken_returns403() throws Exception {
        when(mockRequest.getMethod()).thenReturn("POST");
        // No session — simulates a cross-site request with no session
        when(mockRequest.getSession(false)).thenReturn(null);

        servlet.testProcessRequest(mockRequest, mockResponse);

        verify(mockResponse, times(1))
                .sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid or missing CSRF token");
    }

    /**
     * A POST with a mismatched CSRF token must result in a 403 Forbidden response.
     * This directly tests the CSRF attack vector identified in the finding.
     */
    @Test
    public void testProcessRequest_postWithMismatchedCsrfToken_returns403() throws Exception {
        when(mockRequest.getMethod()).thenReturn("POST");
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("csrfToken")).thenReturn("legitimateSessionToken");
        when(mockRequest.getParameter("csrfToken")).thenReturn("attackerForgery");

        servlet.testProcessRequest(mockRequest, mockResponse);

        verify(mockResponse, times(1))
                .sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid or missing CSRF token");
    }

    /**
     * A GET request must generate a CSRF token (not a state-altering operation)
     * and return a form containing the token — it must NOT call sendError(403).
     */
    @Test
    public void testProcessRequest_getRequest_generatesCsrfTokenAndRenders() throws Exception {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);

        when(mockRequest.getMethod()).thenReturn("GET");
        when(mockRequest.getSession(true)).thenReturn(mockSession);
        when(mockResponse.getWriter()).thenReturn(pw);

        servlet.testProcessRequest(mockRequest, mockResponse);

        // Must NOT have sent a 403
        verify(mockResponse, never()).sendError(anyInt(), anyString());

        // Must have stored a CSRF token in the session
        verify(mockSession, times(1)).setAttribute(eq("csrfToken"), anyString());

        // The rendered output must contain the CSRF hidden field
        String output = sw.toString();
        assertTrue("GET response must embed csrfToken hidden field",
                output.contains("name=\"csrfToken\""));
    }

    /**
     * A POST with a valid CSRF token must pass the CSRF check.
     * (It will fail later at the ServletContext/DB step, but must not return 403.)
     */
    @Test
    public void testProcessRequest_postWithValidCsrfToken_doesNotReturn403() throws Exception {
        String token = "validCsrfToken";
        when(mockRequest.getMethod()).thenReturn("POST");
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("csrfToken")).thenReturn(token);
        when(mockRequest.getParameter("csrfToken")).thenReturn(token);
        // Return null for other params to prevent NPE; setup() is not reached here
        when(mockRequest.getParameter(argThat(p -> !"csrfToken".equals(p)))).thenReturn(null);
        // getServletContext() would throw in a bare test; that's fine — we only verify no 403
        try {
            servlet.testProcessRequest(mockRequest, mockResponse);
        } catch (Exception e) {
            // Expected: ServletContext is unavailable outside a container
        }

        // The critical assertion: a valid token must NOT trigger a 403
        verify(mockResponse, never())
                .sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid or missing CSRF token");
    }
}
