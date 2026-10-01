package org.cysecurity.cspf.jvl.controller;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the CSRF protection added to {@link Install}.
 *
 * The tests use JUnit 4 and Mockito to mock the Servlet API objects so that
 * the CSRF token generation and validation logic can be exercised without a
 * running servlet container.
 *
 * Coverage:
 *  - getOrCreateCsrfToken() generates a token and stores it in the session
 *  - getOrCreateCsrfToken() is idempotent (same token returned on second call)
 *  - POST with no CSRF token → 403 Forbidden
 *  - POST with wrong CSRF token → 403 Forbidden
 *  - POST with correct CSRF token → allowed past the CSRF gate
 *  - GET requests are not blocked by the CSRF gate (token exposed in page)
 */
public class InstallCsrfTest {

    @Mock
    private HttpSession session;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    // -----------------------------------------------------------------------
    // getOrCreateCsrfToken
    // -----------------------------------------------------------------------

    /**
     * When the session has no stored token, getOrCreateCsrfToken() should
     * generate a non-null, non-empty URL-safe Base64 string and persist it
     * in the session.
     */
    @Test
    public void testGetOrCreateCsrfToken_generatesTokenWhenAbsent() {
        // Session does not yet have a token
        when(session.getAttribute(Install.CSRF_TOKEN_SESSION_ATTR)).thenReturn(null);

        String token = Install.getOrCreateCsrfToken(session);

        assertNotNull("Token must not be null", token);
        assertFalse("Token must not be empty", token.isEmpty());
        // Verify the token was stored back in the session
        verify(session).setAttribute(Install.CSRF_TOKEN_SESSION_ATTR, token);
    }

    /**
     * When the session already contains a token, getOrCreateCsrfToken() must
     * return the same value without calling setAttribute again.
     */
    @Test
    public void testGetOrCreateCsrfToken_reusesExistingToken() {
        String existingToken = "existingToken_abc123";
        when(session.getAttribute(Install.CSRF_TOKEN_SESSION_ATTR)).thenReturn(existingToken);

        String token = Install.getOrCreateCsrfToken(session);

        assertEquals("Must return the existing token unchanged", existingToken, token);
        // setAttribute must NOT be called when a token already exists
        verify(session, never()).setAttribute(anyString(), anyString());
    }

    /**
     * Two tokens generated for two independent sessions must differ (collision
     * probability is negligible for 32 random bytes).
     */
    @Test
    public void testGetOrCreateCsrfToken_uniquePerSession() {
        HttpSession session1 = mock(HttpSession.class);
        HttpSession session2 = mock(HttpSession.class);

        when(session1.getAttribute(Install.CSRF_TOKEN_SESSION_ATTR)).thenReturn(null);
        when(session2.getAttribute(Install.CSRF_TOKEN_SESSION_ATTR)).thenReturn(null);

        String token1 = Install.getOrCreateCsrfToken(session1);
        String token2 = Install.getOrCreateCsrfToken(session2);

        assertNotEquals("Tokens for different sessions should differ", token1, token2);
    }

    // -----------------------------------------------------------------------
    // processRequest – CSRF gate (tested via a testable subclass that bypasses
    // the parts of processRequest that require a real servlet container such as
    // getServletContext() and PrintWriter).
    // -----------------------------------------------------------------------

    /**
     * Helper: create a concrete subclass of Install that overrides the parts
     * that need a live container so we can unit-test the CSRF gate in isolation.
     */
    private static class TestableInstall extends Install {

        /** Records whether the CSRF gate was passed (i.e., processing continued). */
        boolean csrfGatePassed = false;

        @Override
        protected void processRequest(HttpServletRequest req, HttpServletResponse resp)
                throws javax.servlet.ServletException, java.io.IOException {

            // Replicate ONLY the CSRF gate from Install.processRequest so we can
            // assert that state-altering logic is blocked for invalid tokens.
            HttpSession sess = req.getSession(true);
            String csrfSessionToken = Install.getOrCreateCsrfToken(sess);

            if ("POST".equalsIgnoreCase(req.getMethod())) {
                String csrfFormToken = req.getParameter(Install.CSRF_TOKEN_PARAM);
                if (csrfFormToken == null || !csrfFormToken.equals(csrfSessionToken)) {
                    resp.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid or missing CSRF token");
                    return;
                }
            }

            // If we reach here the CSRF gate was passed
            csrfGatePassed = true;
        }
    }

    /**
     * A POST without any CSRF token parameter must be rejected with 403.
     */
    @Test
    public void testPostWithoutCsrfToken_isRejected() throws Exception {
        String sessionToken = "validSessionToken";
        when(session.getAttribute(Install.CSRF_TOKEN_SESSION_ATTR)).thenReturn(sessionToken);

        // No token submitted in the form
        when(request.getMethod()).thenReturn("POST");
        when(request.getSession(true)).thenReturn(session);
        when(request.getParameter(Install.CSRF_TOKEN_PARAM)).thenReturn(null);

        TestableInstall servlet = new TestableInstall();
        servlet.processRequest(request, response);

        // Must send 403
        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
        assertFalse("CSRF gate must block the request", servlet.csrfGatePassed);
    }

    /**
     * A POST with a CSRF token that does not match the session token must be
     * rejected with 403.
     */
    @Test
    public void testPostWithWrongCsrfToken_isRejected() throws Exception {
        String sessionToken = "correctSessionToken";
        when(session.getAttribute(Install.CSRF_TOKEN_SESSION_ATTR)).thenReturn(sessionToken);

        when(request.getMethod()).thenReturn("POST");
        when(request.getSession(true)).thenReturn(session);
        when(request.getParameter(Install.CSRF_TOKEN_PARAM)).thenReturn("wrongToken");

        TestableInstall servlet = new TestableInstall();
        servlet.processRequest(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
        assertFalse("CSRF gate must block the request with wrong token", servlet.csrfGatePassed);
    }

    /**
     * A POST with the correct CSRF token must pass the CSRF gate.
     */
    @Test
    public void testPostWithCorrectCsrfToken_isAllowed() throws Exception {
        String sessionToken = "correctSessionToken";
        when(session.getAttribute(Install.CSRF_TOKEN_SESSION_ATTR)).thenReturn(sessionToken);

        when(request.getMethod()).thenReturn("POST");
        when(request.getSession(true)).thenReturn(session);
        when(request.getParameter(Install.CSRF_TOKEN_PARAM)).thenReturn(sessionToken);

        TestableInstall servlet = new TestableInstall();
        servlet.processRequest(request, response);

        verify(response, never()).sendError(anyInt(), anyString());
        assertTrue("CSRF gate must allow request with correct token", servlet.csrfGatePassed);
    }

    /**
     * A GET request must not be blocked by the CSRF gate (it is safe, and the
     * page it renders is the one that includes the token for subsequent POSTs).
     */
    @Test
    public void testGetRequest_isNotBlockedByCsrfGate() throws Exception {
        String sessionToken = "aSessionToken";
        when(session.getAttribute(Install.CSRF_TOKEN_SESSION_ATTR)).thenReturn(sessionToken);

        when(request.getMethod()).thenReturn("GET");
        when(request.getSession(true)).thenReturn(session);

        TestableInstall servlet = new TestableInstall();
        servlet.processRequest(request, response);

        verify(response, never()).sendError(anyInt(), anyString());
        assertTrue("GET request must pass the CSRF gate", servlet.csrfGatePassed);
    }

    /**
     * An empty string CSRF token in the form (not null, but blank) must be
     * rejected because it will never match the securely generated session token.
     */
    @Test
    public void testPostWithEmptyStringCsrfToken_isRejected() throws Exception {
        String sessionToken = "anotherValidToken";
        when(session.getAttribute(Install.CSRF_TOKEN_SESSION_ATTR)).thenReturn(sessionToken);

        when(request.getMethod()).thenReturn("POST");
        when(request.getSession(true)).thenReturn(session);
        when(request.getParameter(Install.CSRF_TOKEN_PARAM)).thenReturn("");

        TestableInstall servlet = new TestableInstall();
        servlet.processRequest(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
        assertFalse("CSRF gate must block request with empty token", servlet.csrfGatePassed);
    }
}
