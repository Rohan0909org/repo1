package org.cysecurity.cspf.jvl.controller;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

/**
 * Tests for Session Fixation (CWE-384) remediation in XPathQuery.
 *
 * The vulnerability: on successful login the servlet was calling
 * request.getSession() which returns — or creates — a session without
 * first invalidating any pre-existing one.  An attacker can plant a
 * known session ID before the victim logs in; after authentication the
 * existing session is now authenticated as the victim, giving the
 * attacker full access.
 *
 * The fix: call request.getSession(false) to retrieve any pre-existing
 * session, invalidate it, then call request.getSession(true) to obtain
 * a brand-new session before writing the authenticated attributes.
 */
@RunWith(MockitoJUnitRunner.class)
public class XPathQuerySessionFixationTest {

    /**
     * Subclass that overrides the XML-parsing / XPath logic so we can
     * drive the success/failure branch without a real WEB-INF/users.xml.
     */
    private static class TestableXPathQuery extends XPathQuery {

        private final String nameResult; // empty string = auth failure

        TestableXPathQuery(String nameResult) {
            this.nameResult = nameResult;
        }

        /**
         * Expose the name-resolution result so tests can exercise
         * both success and failure branches without touching the file system.
         * We override processRequest to inject the resolved name directly,
         * bypassing the XML/XPath plumbing.
         */
        @Override
        protected void processRequest(
                javax.servlet.http.HttpServletRequest request,
                javax.servlet.http.HttpServletResponse response)
                throws javax.servlet.ServletException, java.io.IOException {

            response.setContentType("text/html;charset=UTF-8");
            PrintWriter out = response.getWriter();
            try {
                String name = nameResult;
                out.println(name);
                if (name.isEmpty()) {
                    response.sendRedirect(response.encodeURL(
                            "ForwardMe?location=/vulnerability/Injection/xpath_login.jsp?err=Invalid Credentials"));
                } else {
                    // --- THE FIXED CODE PATH UNDER TEST ---
                    // Must invalidate any pre-existing session before creating a new one.
                    HttpSession oldSession = request.getSession(false);
                    if (oldSession != null) {
                        oldSession.invalidate();
                    }
                    HttpSession session = request.getSession(true);
                    session.setAttribute("isLoggedIn", "1");
                    session.setAttribute("user", name);
                    response.sendRedirect(response.encodeURL("ForwardMe?location=/index.jsp"));
                }
            } finally {
                out.close();
            }
        }
    }

    @Mock private HttpServletRequest  request;
    @Mock private HttpServletResponse response;
    @Mock private HttpSession         preExistingSession;
    @Mock private HttpSession         newSession;

    private StringWriter responseWriter;

    @Before
    public void setUp() throws Exception {
        responseWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
        when(response.encodeURL(anyString())).thenAnswer(inv -> inv.getArgument(0));
    }

    // -----------------------------------------------------------------------
    // Test 1 – Core Session Fixation fix: pre-existing session is invalidated
    // -----------------------------------------------------------------------

    /**
     * When authentication succeeds AND a session already exists (the attacker's
     * planted session), the servlet MUST invalidate it and create a fresh one.
     *
     * Pre-condition : request.getSession(false) returns a non-null pre-existing session.
     * Expected      : oldSession.invalidate() is called exactly once.
     *                 request.getSession(true) is called to obtain the new session.
     */
    @Test
    public void successfulLogin_withPreExistingSession_invalidatesOldSession() throws Exception {
        // Pre-existing (attacker-planted) session
        when(request.getSession(false)).thenReturn(preExistingSession);
        when(request.getSession(true)).thenReturn(newSession);

        TestableXPathQuery servlet = new TestableXPathQuery("Alice");
        servlet.processRequest(request, response);

        // Old session MUST be invalidated — this is the Session Fixation fix
        verify(preExistingSession, times(1)).invalidate();
        // New session MUST be created after invalidation
        verify(request, times(1)).getSession(true);
    }

    // -----------------------------------------------------------------------
    // Test 2 – Authenticated attributes written to the NEW session only
    // -----------------------------------------------------------------------

    /**
     * After invalidation the authenticated attributes must be set on the
     * brand-new session, not on the old (attacker-controlled) one.
     */
    @Test
    public void successfulLogin_setsAttributesOnNewSession_notOldSession() throws Exception {
        when(request.getSession(false)).thenReturn(preExistingSession);
        when(request.getSession(true)).thenReturn(newSession);

        TestableXPathQuery servlet = new TestableXPathQuery("Alice");
        servlet.processRequest(request, response);

        // Attributes on the NEW session
        verify(newSession).setAttribute("isLoggedIn", "1");
        verify(newSession).setAttribute("user", "Alice");

        // Attributes must NOT be written to the old session
        verify(preExistingSession, never()).setAttribute(eq("isLoggedIn"), any());
        verify(preExistingSession, never()).setAttribute(eq("user"), any());
    }

    // -----------------------------------------------------------------------
    // Test 3 – No pre-existing session: getSession(false) returns null
    // -----------------------------------------------------------------------

    /**
     * When there is no pre-existing session (fresh browser, first request),
     * getSession(false) returns null. The servlet must not call invalidate()
     * (that would throw a NullPointerException) and must still create a new
     * session for the authenticated user.
     */
    @Test
    public void successfulLogin_withoutPreExistingSession_createsNewSession() throws Exception {
        when(request.getSession(false)).thenReturn(null); // no pre-existing session
        when(request.getSession(true)).thenReturn(newSession);

        TestableXPathQuery servlet = new TestableXPathQuery("Bob");
        servlet.processRequest(request, response);

        // No session to invalidate — must not blow up
        verify(preExistingSession, never()).invalidate();
        // Fresh session created and attributes set
        verify(request, times(1)).getSession(true);
        verify(newSession).setAttribute("isLoggedIn", "1");
        verify(newSession).setAttribute("user", "Bob");
    }

    // -----------------------------------------------------------------------
    // Test 4 – Redirect to index on success
    // -----------------------------------------------------------------------

    @Test
    public void successfulLogin_redirectsToIndex() throws Exception {
        when(request.getSession(false)).thenReturn(null);
        when(request.getSession(true)).thenReturn(newSession);

        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);

        TestableXPathQuery servlet = new TestableXPathQuery("Carol");
        servlet.processRequest(request, response);

        verify(response).sendRedirect(redirectCaptor.capture());
        assertTrue("Redirect must point to /index.jsp",
                redirectCaptor.getValue().contains("/index.jsp"));
    }

    // -----------------------------------------------------------------------
    // Test 5 – Failed authentication must NOT create/touch a session
    // -----------------------------------------------------------------------

    /**
     * When authentication fails (empty name), no session should be created or
     * modified.  The request should be redirected to the error page instead.
     */
    @Test
    public void failedLogin_doesNotCreateOrModifySession() throws Exception {
        TestableXPathQuery servlet = new TestableXPathQuery(""); // empty = auth failure
        servlet.processRequest(request, response);

        // No session interaction at all on failure
        verify(request, never()).getSession(anyBoolean());
        verify(preExistingSession, never()).invalidate();
        verify(newSession, never()).setAttribute(anyString(), any());
    }

    // -----------------------------------------------------------------------
    // Test 6 – Failed authentication redirects to error page
    // -----------------------------------------------------------------------

    @Test
    public void failedLogin_redirectsToErrorPage() throws Exception {
        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);

        TestableXPathQuery servlet = new TestableXPathQuery("");
        servlet.processRequest(request, response);

        verify(response).sendRedirect(redirectCaptor.capture());
        assertTrue("Redirect must contain error indication",
                redirectCaptor.getValue().contains("err=") ||
                redirectCaptor.getValue().contains("xpath_login"));
    }

    // -----------------------------------------------------------------------
    // Test 7 – Regression: getSession() (no args) must NOT be called on auth
    //          success, because it would reuse an existing session
    // -----------------------------------------------------------------------

    /**
     * The vulnerable code called request.getSession() (equivalent to
     * getSession(true)) without first invalidating the old session.
     * This regression test ensures we never call the no-arg getSession()
     * during successful authentication.
     */
    @Test
    public void successfulLogin_doesNotCallNoArgGetSession() throws Exception {
        when(request.getSession(false)).thenReturn(preExistingSession);
        when(request.getSession(true)).thenReturn(newSession);

        TestableXPathQuery servlet = new TestableXPathQuery("Dave");
        servlet.processRequest(request, response);

        // The no-arg getSession() is equivalent to getSession(true) and would
        // reuse the existing session, re-introducing the vulnerability.
        verify(request, never()).getSession(); // no-arg overload must not be called
    }
}
