package org.cysecurity.cspf.jvl.controller;

/*
 * Tests for CSRF protection in the Install servlet.
 *
 * These tests verify that the synchronizer-token pattern added to
 * processRequest() correctly:
 *   1. Rejects requests that carry no CSRF token.
 *   2. Rejects requests that carry a token that does not match the session.
 *   3. Rejects requests when no session exists at all.
 *   4. Allows requests that carry the correct CSRF token.
 *   5. getCsrfToken() generates and re-uses a per-session token.
 *
 * Because Install is a plain javax.servlet.HttpServlet with no dependency-
 * injection seams, all collaborators (request, response, session) are
 * Mockito mocks.
 */

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.servlet.ServletContext;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.lang.reflect.Method;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class InstallCsrfTest {

    /** Concrete subclass that overrides getServletContext() so the servlet
     *  can be tested without a running container. */
    private static class TestableInstall extends Install {
        private final ServletContext ctx;

        TestableInstall(ServletContext ctx) {
            this.ctx = ctx;
        }

        @Override
        public ServletContext getServletContext() {
            return ctx;
        }
    }

    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private HttpSession session;
    @Mock private ServletContext servletContext;
    @Mock private ServletConfig servletConfig;

    private TestableInstall servlet;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        // Wire up the servlet with a mock context so init() does not throw.
        when(servletConfig.getServletContext()).thenReturn(servletContext);
        servlet = new TestableInstall(servletContext);
        servlet.init(servletConfig);
    }

    // -----------------------------------------------------------------------
    // Helper: call the private getCsrfToken() via reflection.
    // -----------------------------------------------------------------------
    private String invokeCsrfTokenHelper(HttpSession s) throws Exception {
        Method m = Install.class.getDeclaredMethod("getCsrfToken", HttpSession.class);
        m.setAccessible(true);
        return (String) m.invoke(servlet, s);
    }

    // -----------------------------------------------------------------------
    // 1. No CSRF token in the request → 403 Forbidden
    // -----------------------------------------------------------------------
    @Test
    public void processRequest_missingToken_returns403() throws Exception {
        // Session exists and holds a valid token, but the form does NOT submit one.
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("csrfToken")).thenReturn("validToken");
        when(request.getParameter("csrfToken")).thenReturn(null);

        servlet.doPost(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
        // State-altering parameters must not have been read after the CSRF check.
        verify(request, never()).getParameter("dbuser");
        verify(request, never()).getParameter("setup");
    }

    // -----------------------------------------------------------------------
    // 2. Wrong CSRF token in the request → 403 Forbidden
    // -----------------------------------------------------------------------
    @Test
    public void processRequest_wrongToken_returns403() throws Exception {
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("csrfToken")).thenReturn("correctToken");
        when(request.getParameter("csrfToken")).thenReturn("attackerForgedToken");

        servlet.doPost(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
        verify(request, never()).getParameter("dbuser");
    }

    // -----------------------------------------------------------------------
    // 3. Empty string CSRF token in the request → 403 Forbidden
    // -----------------------------------------------------------------------
    @Test
    public void processRequest_emptyToken_returns403() throws Exception {
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("csrfToken")).thenReturn("correctToken");
        when(request.getParameter("csrfToken")).thenReturn("");

        servlet.doPost(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
    }

    // -----------------------------------------------------------------------
    // 4. No session at all (session(false) returns null) → 403 Forbidden
    // -----------------------------------------------------------------------
    @Test
    public void processRequest_noSession_returns403() throws Exception {
        when(request.getSession(false)).thenReturn(null);
        when(request.getParameter("csrfToken")).thenReturn("anyToken");

        servlet.doPost(request, response);

        verify(response).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
    }

    // -----------------------------------------------------------------------
    // 5. Correct CSRF token → request proceeds past the CSRF gate
    //    (i.e. sendError is NOT called for 403)
    // -----------------------------------------------------------------------
    @Test
    public void processRequest_correctToken_proceedsPastCsrfGate() throws Exception {
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("csrfToken")).thenReturn("goodToken");
        when(request.getParameter("csrfToken")).thenReturn("goodToken");

        // Stub parameters that processRequest reads after the CSRF check.
        // We deliberately do NOT stub getServletContext().getRealPath() here so
        // the servlet will throw before touching the database — which is fine
        // because we only need to assert that sendError(403) was NOT called.
        when(request.getParameter("dburl")).thenReturn("jdbc:mysql://localhost/");
        when(request.getParameter("jdbcdriver")).thenReturn("com.mysql.jdbc.Driver");
        when(request.getParameter("dbuser")).thenReturn("root");
        when(request.getParameter("dbpass")).thenReturn("pass");
        when(request.getParameter("dbname")).thenReturn("testdb");
        when(request.getParameter("siteTitle")).thenReturn("Title");
        when(request.getParameter("adminuser")).thenReturn("admin");
        when(request.getParameter("adminpass")).thenReturn("secret");
        when(request.getParameter("setup")).thenReturn("0");
        // Returning null from getRealPath makes FileInputStream throw, but that
        // happens inside a catch(Exception) block so the test won't explode.
        when(servletContext.getRealPath("/WEB-INF/config.properties")).thenReturn(null);

        servlet.doPost(request, response);

        // The CSRF gate must NOT have rejected the request with 403.
        ArgumentCaptor<Integer> codeCaptor = ArgumentCaptor.forClass(Integer.class);
        // Verify sendError was NOT called with 403.
        verify(response, never()).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
    }

    // -----------------------------------------------------------------------
    // 6. getCsrfToken() generates a non-null, URL-safe token on first call
    // -----------------------------------------------------------------------
    @Test
    public void getCsrfToken_generatesNonNullToken() throws Exception {
        when(session.getAttribute("csrfToken")).thenReturn(null);

        String token = invokeCsrfTokenHelper(session);

        assertNotNull("CSRF token must not be null", token);
        assertFalse("CSRF token must not be empty", token.isEmpty());
        // Token must be URL-safe Base64 (no '+', '/', or '=' padding).
        assertFalse("Token must not contain '+'", token.contains("+"));
        assertFalse("Token must not contain '/'", token.contains("/"));
        assertFalse("Token must not contain '='", token.contains("="));
        verify(session).setAttribute("csrfToken", token);
    }

    // -----------------------------------------------------------------------
    // 7. getCsrfToken() returns the existing token when one is already set
    // -----------------------------------------------------------------------
    @Test
    public void getCsrfToken_reuseExistingToken() throws Exception {
        String existingToken = "alreadyStoredToken";
        when(session.getAttribute("csrfToken")).thenReturn(existingToken);

        String token = invokeCsrfTokenHelper(session);

        assertEquals("Must return the existing session token", existingToken, token);
        // Must NOT overwrite the existing token.
        verify(session, never()).setAttribute(anyString(), anyString());
    }

    // -----------------------------------------------------------------------
    // 8. getCsrfToken() produces tokens with sufficient entropy (>=32 bytes
    //    of raw randomness encoded as at least 43 Base64Url characters)
    // -----------------------------------------------------------------------
    @Test
    public void getCsrfToken_tokenHasSufficientLength() throws Exception {
        when(session.getAttribute("csrfToken")).thenReturn(null);

        String token = invokeCsrfTokenHelper(session);

        // 32 random bytes encoded with Base64Url without padding → 43 chars minimum.
        assertTrue("Token must be at least 43 characters long", token.length() >= 43);
    }

    // -----------------------------------------------------------------------
    // 9. Two successive calls to getCsrfToken() with a fresh session produce
    //    different tokens (randomness check)
    // -----------------------------------------------------------------------
    @Test
    public void getCsrfToken_twoFreshSessionsProduceDifferentTokens() throws Exception {
        HttpSession session1 = mock(HttpSession.class);
        HttpSession session2 = mock(HttpSession.class);
        when(session1.getAttribute("csrfToken")).thenReturn(null);
        when(session2.getAttribute("csrfToken")).thenReturn(null);

        String token1 = invokeCsrfTokenHelper(session1);
        String token2 = invokeCsrfTokenHelper(session2);

        assertNotEquals("Tokens for different sessions must be different", token1, token2);
    }
}
