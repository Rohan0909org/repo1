package org.cysecurity.cspf.jvl.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for the CSRF protection added to the Install servlet (CWE-352).
 *
 * The fix introduces a synchronizer-token pattern:
 *   1. GET /Install  → generates a per-session CSRF token stored in the
 *                      HttpSession and embeds it as a hidden form field.
 *   2. POST /Install → rejects the request with HTTP 403 if the submitted
 *                      token is absent, null, or does not match the session
 *                      token; only proceeds when they match exactly.
 *
 * These tests verify both the token-generation path (happy path) and the
 * rejection path (attack vector) without touching a real database or
 * servlet container.
 */
@ExtendWith(MockitoExtension.class)
class InstallCsrfTest {

    private Install servlet;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @BeforeEach
    void setUp() {
        servlet = new Install();
    }

    // -----------------------------------------------------------------------
    // getOrCreateCsrfToken — token generation
    // -----------------------------------------------------------------------

    /**
     * When no token is stored in the session a new token must be generated,
     * stored back into the session, and returned.
     */
    @Test
    void getOrCreateCsrfToken_createsTokenWhenAbsent() {
        when(session.getAttribute(Install.CSRF_TOKEN_ATTR)).thenReturn(null);

        String token = servlet.getOrCreateCsrfToken(session);

        assertNotNull(token, "token must not be null");
        assertFalse(token.isEmpty(), "token must not be empty");
        // Must be stored in the session for subsequent validation.
        verify(session).setAttribute(Install.CSRF_TOKEN_ATTR, token);
    }

    /**
     * When a token already exists in the session it must be returned as-is
     * without creating a new one (so the form token and the session token
     * remain identical across page loads).
     */
    @Test
    void getOrCreateCsrfToken_reusesExistingToken() {
        String existingToken = "existing-csrf-token-value";
        when(session.getAttribute(Install.CSRF_TOKEN_ATTR)).thenReturn(existingToken);

        String token = servlet.getOrCreateCsrfToken(session);

        assertEquals(existingToken, token);
        // Must NOT overwrite the existing token.
        verify(session, never()).setAttribute(eq(Install.CSRF_TOKEN_ATTR), any());
    }

    /**
     * Two successive calls with an empty session must return the same token
     * (no new token generated on the second call).
     */
    @Test
    void getOrCreateCsrfToken_secondCallReturnsSameToken() {
        // Simulate setAttribute side-effect so the second getAttribute returns
        // the token that was stored on the first call.
        ArgumentCaptor<String> storedToken = ArgumentCaptor.forClass(String.class);

        // First call: no token present.
        when(session.getAttribute(Install.CSRF_TOKEN_ATTR))
                .thenReturn(null)
                .thenAnswer(inv -> storedToken.getValue());
        doAnswer(inv -> { storedToken.capture(); return null; })
                .when(session).setAttribute(eq(Install.CSRF_TOKEN_ATTR), anyString());

        String first  = servlet.getOrCreateCsrfToken(session);
        String second = servlet.getOrCreateCsrfToken(session);

        assertEquals(first, second, "same token must be returned on subsequent calls");
    }

    /**
     * Generated tokens must be unique across different sessions (statistically).
     */
    @Test
    void getOrCreateCsrfToken_generatesUniqueTokensPerSession() {
        HttpSession session2 = mock(HttpSession.class);
        when(session.getAttribute(Install.CSRF_TOKEN_ATTR)).thenReturn(null);
        when(session2.getAttribute(Install.CSRF_TOKEN_ATTR)).thenReturn(null);

        String token1 = servlet.getOrCreateCsrfToken(session);
        String token2 = servlet.getOrCreateCsrfToken(session2);

        assertNotEquals(token1, token2,
                "tokens for different sessions must be distinct");
    }

    // -----------------------------------------------------------------------
    // processRequest — CSRF validation (the taint-flow sink)
    // -----------------------------------------------------------------------

    /**
     * ATTACK VECTOR: request submitted with NO session (i.e. cross-site
     * request before the victim has ever visited the install page).
     * Must be rejected with HTTP 403.
     */
    @Test
    void processRequest_rejectsRequestWithNoSession() throws Exception {
        // getSession(false) returns null → no active session
        when(request.getSession(false)).thenReturn(null);
        when(request.getParameter(Install.CSRF_TOKEN_PARAM)).thenReturn("any-token");

        servlet.processRequest(request, response);

        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN,
                "CSRF token validation failed.");
    }

    /**
     * ATTACK VECTOR: cross-site POST with no CSRF token parameter at all.
     * Must be rejected with HTTP 403.
     */
    @Test
    void processRequest_rejectsMissingCsrfTokenParameter() throws Exception {
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute(Install.CSRF_TOKEN_ATTR))
                .thenReturn("valid-session-token");
        // Attacker's form does not include the hidden csrfToken field.
        when(request.getParameter(Install.CSRF_TOKEN_PARAM)).thenReturn(null);

        servlet.processRequest(request, response);

        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN,
                "CSRF token validation failed.");
    }

    /**
     * ATTACK VECTOR: cross-site POST with an incorrect CSRF token
     * (attacker guesses / forges a value).
     * Must be rejected with HTTP 403.
     */
    @Test
    void processRequest_rejectsWrongCsrfToken() throws Exception {
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute(Install.CSRF_TOKEN_ATTR))
                .thenReturn("correct-session-token");
        when(request.getParameter(Install.CSRF_TOKEN_PARAM))
                .thenReturn("attacker-guessed-token");

        servlet.processRequest(request, response);

        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN,
                "CSRF token validation failed.");
    }

    /**
     * ATTACK VECTOR: CSRF token present in session but empty string submitted.
     * Must be rejected with HTTP 403.
     */
    @Test
    void processRequest_rejectsEmptySubmittedCsrfToken() throws Exception {
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute(Install.CSRF_TOKEN_ATTR))
                .thenReturn("valid-session-token");
        when(request.getParameter(Install.CSRF_TOKEN_PARAM)).thenReturn("");

        servlet.processRequest(request, response);

        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN,
                "CSRF token validation failed.");
    }

    /**
     * ATTACK VECTOR: session exists but has no CSRF token stored
     * (session fixation / token not yet issued).
     * Must be rejected with HTTP 403.
     */
    @Test
    void processRequest_rejectsWhenSessionHasNoToken() throws Exception {
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute(Install.CSRF_TOKEN_ATTR)).thenReturn(null);
        when(request.getParameter(Install.CSRF_TOKEN_PARAM))
                .thenReturn("any-submitted-token");

        servlet.processRequest(request, response);

        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN,
                "CSRF token validation failed.");
    }

    /**
     * HAPPY PATH: valid CSRF token submitted — the request must NOT be
     * rejected with sendError(403).  (Full processing requires a servlet
     * context; we just verify the guard does not fire.)
     *
     * Note: processRequest will throw after the CSRF check because
     * getServletContext() returns null in a unit test — that is expected
     * and does not indicate a CSRF bypass.
     */
    @Test
    void processRequest_allowsRequestWithValidCsrfToken() throws Exception {
        String validToken = "correctly-matching-token";
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute(Install.CSRF_TOKEN_ATTR)).thenReturn(validToken);
        when(request.getParameter(Install.CSRF_TOKEN_PARAM)).thenReturn(validToken);

        // The method will proceed past the CSRF check and then likely throw a
        // NullPointerException (no servlet context) — that is acceptable here;
        // what matters is that sendError(403) is NEVER called.
        try {
            servlet.processRequest(request, response);
        } catch (Exception ignored) {
            // Expected: NPE from getServletContext() in a unit-test context.
        }

        // The CSRF guard must not have fired.
        verify(response, never()).sendError(
                eq(HttpServletResponse.SC_FORBIDDEN), anyString());
    }

    // -----------------------------------------------------------------------
    // doGet — CSRF token must be embedded in the form
    // -----------------------------------------------------------------------

    /**
     * doGet must create a new session (or reuse an existing one), generate a
     * CSRF token, and render the install form with that token as a hidden field.
     */
    @Test
    void doGet_embedsCsrfTokenInForm() throws Exception {
        StringWriter body = new StringWriter();
        PrintWriter writer = new PrintWriter(body);

        when(request.getSession(true)).thenReturn(session);
        when(session.getAttribute(Install.CSRF_TOKEN_ATTR)).thenReturn(null);
        when(response.getWriter()).thenReturn(writer);

        // Capture the token stored by getOrCreateCsrfToken.
        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        doNothing().when(session).setAttribute(
                eq(Install.CSRF_TOKEN_ATTR), tokenCaptor.capture());

        servlet.doGet(request, response);

        String html = body.toString();
        String storedToken = tokenCaptor.getValue();

        assertNotNull(storedToken, "a CSRF token must have been stored in the session");
        assertTrue(html.contains("name=\"" + Install.CSRF_TOKEN_PARAM + "\""),
                "form must contain a field named '" + Install.CSRF_TOKEN_PARAM + "'");
        assertTrue(html.contains("value=\"" + storedToken + "\""),
                "form must embed the generated CSRF token as the field value");
        assertTrue(html.contains("type=\"hidden\""),
                "the CSRF token field must be a hidden input");
    }

    // -----------------------------------------------------------------------
    // Constant values — prevent accidental renames that break the protocol
    // -----------------------------------------------------------------------

    @Test
    void csrfConstants_haveExpectedValues() {
        assertEquals("csrfToken", Install.CSRF_TOKEN_ATTR);
        assertEquals("csrfToken", Install.CSRF_TOKEN_PARAM);
    }
}
