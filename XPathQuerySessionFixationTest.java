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
import javax.servlet.http.HttpSession;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Tests for Session Fixation (CWE-384) remediation in XPathQuery.
 *
 * The key security requirement: upon successful authentication the servlet must
 * invalidate any pre-existing session and issue a brand-new one, so an attacker
 * who planted a known session ID cannot have it elevated to an authenticated state.
 */
@RunWith(MockitoJUnitRunner.class)
public class XPathQuerySessionFixationTest {

    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private HttpSession existingSession;   // session that existed BEFORE login
    @Mock private HttpSession newSession;        // session created AFTER login
    @Mock private ServletContext servletContext;

    private StringWriter responseWriter;

    @Before
    public void setUp() throws Exception {
        responseWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));

        // Provide a real users.xml for the XPath evaluation via a temp file.
        // The XML contains one valid user: alice / secret123.
        String usersXml =
            "<?xml version=\"1.0\"?>" +
            "<users>" +
            "  <user>" +
            "    <username>alice</username>" +
            "    <password>secret123</password>" +
            "    <name>Alice Smith</name>" +
            "  </user>" +
            "</users>";
        java.io.File tmpXml = java.io.File.createTempFile("users", ".xml");
        tmpXml.deleteOnExit();
        try (java.io.FileWriter fw = new java.io.FileWriter(tmpXml)) {
            fw.write(usersXml);
        }

        when(servletContext.getRealPath("/WEB-INF/users.xml")).thenReturn(tmpXml.getAbsolutePath());
    }

    // -----------------------------------------------------------------------
    // Helper: build a servlet with a mocked ServletContext
    // -----------------------------------------------------------------------
    private XPathQuery buildServlet() throws Exception {
        XPathQuery servlet = new XPathQuery() {
            @Override
            public ServletContext getServletContext() {
                return servletContext;
            }
        };
        return servlet;
    }

    // -----------------------------------------------------------------------
    // Security test: existing session MUST be invalidated on successful login
    // -----------------------------------------------------------------------

    /**
     * An attacker pre-establishes a session (existingSession) and tricks the
     * victim into logging in.  The servlet MUST call existingSession.invalidate()
     * before attaching any authentication attributes.
     */
    @Test
    public void testExistingSessionIsInvalidatedOnSuccessfulLogin() throws Exception {
        // Arrange: attacker-controlled session already exists
        when(request.getParameter("username")).thenReturn("alice");
        when(request.getParameter("password")).thenReturn("secret123");
        // getSession(false) returns the pre-existing (attacker-controlled) session
        when(request.getSession(false)).thenReturn(existingSession);
        // getSession(true) returns the fresh session issued post-login
        when(request.getSession(true)).thenReturn(newSession);

        XPathQuery servlet = buildServlet();

        // Act
        servlet.processRequest(request, response);

        // Assert: the old session was invalidated (preventing session fixation)
        verify(existingSession, times(1)).invalidate();
    }

    /**
     * After invalidating the old session, the servlet must create a new session
     * (getSession(true)) and attach the authentication attributes to it — never
     * to the old, invalidated one.
     */
    @Test
    public void testNewSessionCreatedAndAttributesSetOnNewSession() throws Exception {
        when(request.getParameter("username")).thenReturn("alice");
        when(request.getParameter("password")).thenReturn("secret123");
        when(request.getSession(false)).thenReturn(existingSession);
        when(request.getSession(true)).thenReturn(newSession);

        XPathQuery servlet = buildServlet();
        servlet.processRequest(request, response);

        // Authentication attributes must be set on the NEW session only
        verify(newSession).setAttribute("isLoggedIn", "1");
        verify(newSession).setAttribute(eq("user"), anyString());

        // The old (attacker-controlled) session must NOT receive auth attributes
        verify(existingSession, never()).setAttribute(eq("isLoggedIn"), any());
        verify(existingSession, never()).setAttribute(eq("user"), any());
    }

    /**
     * If no session existed before login (normal first-visit case) the servlet
     * must still work: getSession(false) returns null, so there is nothing to
     * invalidate, and getSession(true) creates the first session.
     */
    @Test
    public void testLoginWorksWhenNoPriorSessionExists() throws Exception {
        when(request.getParameter("username")).thenReturn("alice");
        when(request.getParameter("password")).thenReturn("secret123");
        // No prior session
        when(request.getSession(false)).thenReturn(null);
        when(request.getSession(true)).thenReturn(newSession);

        XPathQuery servlet = buildServlet();
        servlet.processRequest(request, response);

        // No invalidate call (nothing to invalidate)
        verify(existingSession, never()).invalidate();

        // New session gets auth attributes
        verify(newSession).setAttribute("isLoggedIn", "1");
        verify(newSession).setAttribute(eq("user"), anyString());
    }

    // -----------------------------------------------------------------------
    // Functional test: failed login must NOT touch any session
    // -----------------------------------------------------------------------

    /**
     * When credentials are wrong the user is NOT authenticated.  No session
     * attributes should be set and the old session must NOT be invalidated.
     */
    @Test
    public void testFailedLoginDoesNotSetSessionAttributes() throws Exception {
        when(request.getParameter("username")).thenReturn("alice");
        when(request.getParameter("password")).thenReturn("wrongpassword");
        // A session may or may not exist; irrelevant for failed login
        when(request.getSession(false)).thenReturn(existingSession);

        XPathQuery servlet = buildServlet();
        servlet.processRequest(request, response);

        // Neither the old nor any new session should have isLoggedIn set
        verify(existingSession, never()).setAttribute(eq("isLoggedIn"), any());
        verify(newSession, never()).setAttribute(any(), any());
        // Old session should NOT be invalidated for a failed login attempt
        verify(existingSession, never()).invalidate();
    }

    // -----------------------------------------------------------------------
    // Regression test: getSession() (no args) must NOT be used for auth session
    // -----------------------------------------------------------------------

    /**
     * The vulnerable pattern was request.getSession() (no argument), which
     * silently reuses any existing session.  After the fix, the servlet must
     * only call getSession(false) to inspect an existing session and
     * getSession(true) to create a brand-new one.  It must NOT call
     * getSession() (the zero-arg overload that reuses existing sessions).
     *
     * We verify this indirectly: the zero-arg getSession() is never invoked
     * on a successful auth path.
     */
    @Test
    public void testZeroArgGetSessionNeverCalledOnSuccessfulLogin() throws Exception {
        when(request.getParameter("username")).thenReturn("alice");
        when(request.getParameter("password")).thenReturn("secret123");
        when(request.getSession(false)).thenReturn(existingSession);
        when(request.getSession(true)).thenReturn(newSession);

        XPathQuery servlet = buildServlet();
        servlet.processRequest(request, response);

        // getSession() (zero-arg) must never be called; only getSession(boolean)
        verify(request, never()).getSession();
    }

    // -----------------------------------------------------------------------
    // Redirect test: successful login redirects to index
    // -----------------------------------------------------------------------

    @Test
    public void testSuccessfulLoginRedirectsToIndex() throws Exception {
        when(request.getParameter("username")).thenReturn("alice");
        when(request.getParameter("password")).thenReturn("secret123");
        when(request.getSession(false)).thenReturn(existingSession);
        when(request.getSession(true)).thenReturn(newSession);

        // encodeURL just returns its argument in tests
        when(response.encodeURL(anyString())).thenAnswer(inv -> inv.getArguments()[0]);

        XPathQuery servlet = buildServlet();
        servlet.processRequest(request, response);

        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);
        verify(response).sendRedirect(redirectCaptor.capture());
        assertTrue("Redirect should point to index.jsp",
                redirectCaptor.getValue().contains("index.jsp"));
    }

    // -----------------------------------------------------------------------
    // Redirect test: failed login redirects to error page
    // -----------------------------------------------------------------------

    @Test
    public void testFailedLoginRedirectsToErrorPage() throws Exception {
        when(request.getParameter("username")).thenReturn("alice");
        when(request.getParameter("password")).thenReturn("bad");
        when(request.getSession(false)).thenReturn(null);
        when(response.encodeURL(anyString())).thenAnswer(inv -> inv.getArguments()[0]);

        XPathQuery servlet = buildServlet();
        servlet.processRequest(request, response);

        ArgumentCaptor<String> redirectCaptor = ArgumentCaptor.forClass(String.class);
        verify(response).sendRedirect(redirectCaptor.capture());
        assertTrue("Redirect should indicate invalid credentials",
                redirectCaptor.getValue().contains("Invalid Credentials") ||
                redirectCaptor.getValue().contains("xpath_login"));
    }
}
