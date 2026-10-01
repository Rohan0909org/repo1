package org.cysecurity.cspf.jvl.controller;

import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the CSRF protection added to Install.java.
 *
 * These tests verify that:
 *   1. getOrCreateCsrfToken() generates a non-null, non-empty token and stores
 *      it in the session.
 *   2. Calling getOrCreateCsrfToken() twice with the same session returns the
 *      same token (idempotent).
 *   3. Different sessions receive different CSRF tokens.
 *   4. doPost() returns 403 Forbidden when no CSRF token is present in the
 *      request (absent form token).
 *   5. doPost() returns 403 Forbidden when the session has no CSRF token.
 *   6. doPost() returns 403 Forbidden when the form token does not match the
 *      session token (token mismatch — simulates a cross-site forged request).
 *   7. doPost() proceeds normally when the form token matches the session token
 *      (valid same-origin request).
 *   8. A forged POST with a guessed / fabricated token is rejected (simulates
 *      an attacker supplying their own token without a matching session).
 */
public class InstallCsrfTest {

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Minimal in-memory HttpSession stub that stores attributes in a Map.
     * Using a real Map ensures getAttribute/setAttribute semantics match the
     * servlet spec without introducing reflection or dynamic proxies.
     */
    static class StubSession implements HttpSession {
        private final Map<String, Object> attrs = new HashMap<>();

        @Override
        public Object getAttribute(String name) { return attrs.get(name); }

        @Override
        public void setAttribute(String name, Object value) { attrs.put(name, value); }

        @Override
        public void removeAttribute(String name) { attrs.remove(name); }

        // Unused methods — minimal stubs so the class compiles
        @Override public String getId() { return "stub-session-id"; }
        @Override public long getCreationTime() { return 0; }
        @Override public long getLastAccessedTime() { return 0; }
        @Override public javax.servlet.ServletContext getServletContext() { return null; }
        @Override public void setMaxInactiveInterval(int interval) {}
        @Override public int getMaxInactiveInterval() { return 0; }
        @Override @SuppressWarnings("deprecation") public javax.servlet.http.HttpSessionContext getSessionContext() { return null; }
        @Override public Object getValue(String name) { return attrs.get(name); }
        @Override public java.util.Enumeration<String> getAttributeNames() { return java.util.Collections.enumeration(attrs.keySet()); }
        @Override public String[] getValueNames() { return attrs.keySet().toArray(new String[0]); }
        @Override public void putValue(String name, Object value) { attrs.put(name, value); }
        @Override public void removeValue(String name) { attrs.remove(name); }
        @Override public void invalidate() { attrs.clear(); }
        @Override public boolean isNew() { return false; }
    }

    // -----------------------------------------------------------------------
    // Token generation tests (do NOT require a live servlet container)
    // -----------------------------------------------------------------------

    /**
     * getOrCreateCsrfToken should produce a non-null, non-empty string and
     * store it in the session under CSRF_TOKEN_ATTR.
     */
    @Test
    public void testGetOrCreateCsrfToken_generatesToken() {
        StubSession session = new StubSession();
        String token = Install.getOrCreateCsrfToken(session);

        assertNotNull("Token must not be null", token);
        assertFalse("Token must not be empty", token.isEmpty());
        assertEquals("Token must be stored in session",
                token, session.getAttribute(Install.CSRF_TOKEN_ATTR));
    }

    /**
     * Calling getOrCreateCsrfToken twice with the same session must return the
     * same token (the existing token is reused, not replaced).
     */
    @Test
    public void testGetOrCreateCsrfToken_idempotent() {
        StubSession session = new StubSession();
        String firstCall  = Install.getOrCreateCsrfToken(session);
        String secondCall = Install.getOrCreateCsrfToken(session);

        assertEquals("Second call must return the same token", firstCall, secondCall);
    }

    /**
     * Two independent sessions must receive different CSRF tokens (ensuring
     * the tokens are not a hard-coded constant).
     */
    @Test
    public void testGetOrCreateCsrfToken_uniquePerSession() {
        String token1 = Install.getOrCreateCsrfToken(new StubSession());
        String token2 = Install.getOrCreateCsrfToken(new StubSession());

        assertNotEquals("Different sessions must get different tokens", token1, token2);
    }

    /**
     * CSRF tokens must be at least 32 characters long to ensure sufficient
     * entropy (Base64url encoding of 32 bytes produces 43 characters without
     * padding).
     */
    @Test
    public void testGetOrCreateCsrfToken_sufficientLength() {
        String token = Install.getOrCreateCsrfToken(new StubSession());
        assertTrue("Token must be at least 32 characters for sufficient entropy",
                token.length() >= 32);
    }

    // -----------------------------------------------------------------------
    // doPost CSRF validation tests — use Mockito mocks for the servlet API
    // -----------------------------------------------------------------------

    private Install servlet;
    private HttpServletResponse response;

    @Before
    public void setUp() {
        servlet  = new Install();
        response = mock(HttpServletResponse.class);
    }

    /**
     * A POST with no session at all must be rejected with 403 Forbidden.
     * This simulates a request where the attacker has never established a
     * legitimate session.
     */
    @Test
    public void testDoPost_noSession_returns403() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getSession(false)).thenReturn(null);
        when(request.getParameter("csrfToken")).thenReturn("any-token");

        servlet.doPost(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
    }

    /**
     * A POST without a csrfToken parameter must be rejected with 403
     * (missing form token — e.g. an API-style cross-origin request).
     */
    @Test
    public void testDoPost_missingFormToken_returns403() throws Exception {
        StubSession session = new StubSession();
        // Session has a valid token
        Install.getOrCreateCsrfToken(session);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getSession(false)).thenReturn(session);
        when(request.getParameter("csrfToken")).thenReturn(null); // no token in form

        servlet.doPost(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
    }

    /**
     * A POST where the form token does not match the session token must be
     * rejected with 403.  This is the core CSRF attack scenario: an attacker
     * forges a form with an incorrect token.
     */
    @Test
    public void testDoPost_wrongToken_returns403() throws Exception {
        StubSession session = new StubSession();
        Install.getOrCreateCsrfToken(session); // legitimate session token

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getSession(false)).thenReturn(session);
        // Attacker submits a fabricated / guessed token
        when(request.getParameter("csrfToken")).thenReturn("attacker-fabricated-token");

        servlet.doPost(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
    }

    /**
     * A POST where the session has no CSRF token stored (e.g. session was
     * invalidated and recreated without going through doGet) must be rejected.
     */
    @Test
    public void testDoPost_emptySessionToken_returns403() throws Exception {
        StubSession session = new StubSession();
        // Deliberately do NOT call getOrCreateCsrfToken — session has no token

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getSession(false)).thenReturn(session);
        when(request.getParameter("csrfToken")).thenReturn("some-token");

        servlet.doPost(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
    }

    /**
     * A POST with a valid CSRF token (form token matches session token) must
     * NOT be rejected with 403; the CSRF guard must pass.
     *
     * Note: processRequest() reads config files and connects to a database,
     * so it will throw an exception here (no live container/DB).  We verify
     * only that sendError(403, ...) is NOT called — meaning the CSRF check
     * passed and the request was handed to processRequest().
     */
    @Test
    public void testDoPost_validToken_passesGuard() throws Exception {
        StubSession session = new StubSession();
        String validToken = Install.getOrCreateCsrfToken(session);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getSession(false)).thenReturn(session);
        when(request.getParameter("csrfToken")).thenReturn(validToken);
        // processRequest() will call getServletContext() — let it return null
        // so it throws NullPointerException internally; we only check the
        // CSRF guard layer does NOT invoke sendError(403, ...).
        when(request.getParameter(argThat(s -> s != null && !s.equals("csrfToken"))))
                .thenReturn(null);

        try {
            servlet.doPost(request, response);
        } catch (Exception ignored) {
            // Expected: processRequest() fails without a servlet container —
            // what matters is that 403 was NOT sent.
        }

        // The CSRF guard must not have rejected this valid-token request
        verify(response, never()).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
    }

    /**
     * Simulate a full CSRF attack: the attacker has their own session with their
     * own token, but tries to trick the victim into submitting a form.
     *
     * The victim's session contains token A; the forged form carries the
     * attacker's token B.  The server must reject the request with 403.
     */
    @Test
    public void testDoPost_csrfAttackScenario_rejected() throws Exception {
        // Victim's session
        StubSession victimSession = new StubSession();
        String victimToken = Install.getOrCreateCsrfToken(victimSession);

        // Attacker's own session (they visit the page to get their own token)
        StubSession attackerSession = new StubSession();
        String attackerToken = Install.getOrCreateCsrfToken(attackerSession);

        // Sanity check: attacker and victim have different tokens
        assertNotEquals("Victim and attacker tokens must differ", victimToken, attackerToken);

        // The forged cross-site request arrives with the victim's session cookie
        // but the attacker's CSRF token (attacker cannot read the victim's token
        // due to Same-Origin Policy — here we verify the mismatch causes rejection)
        HttpServletRequest forgedRequest = mock(HttpServletRequest.class);
        when(forgedRequest.getSession(false)).thenReturn(victimSession); // victim session
        when(forgedRequest.getParameter("csrfToken")).thenReturn(attackerToken); // wrong token

        servlet.doPost(forgedRequest, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
    }
}
