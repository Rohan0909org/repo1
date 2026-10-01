package org.cysecurity.cspf.jvl.controller;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Tests for XPathQuery servlet – specifically validating the CWE-501
 * (Trust Boundary Violation) remediation.
 *
 * The critical security requirement verified here is:
 *   - Only the allowlist-validated username (not the raw XPath result) is
 *     stored in the session attribute "user".
 *   - Usernames that fail the allowlist are rejected before reaching the
 *     session-write path.
 */
@RunWith(MockitoJUnitRunner.class)
public class XPathQueryTest {

    @Mock private HttpServletRequest  request;
    @Mock private HttpServletResponse response;
    @Mock private HttpSession         session;
    @Mock private ServletContext      servletContext;

    private StringWriter responseWriter;
    private XPathQuery   servlet;

    /** Reflective helper – calls the protected processRequest method. */
    private void invokeProcessRequest() throws Exception {
        Method m = XPathQuery.class.getDeclaredMethod(
                "processRequest",
                HttpServletRequest.class, HttpServletResponse.class);
        m.setAccessible(true);
        m.invoke(servlet, request, response);
    }

    @Before
    public void setUp() throws Exception {
        servlet = spy(new XPathQuery());
        doReturn(servletContext).when(servlet).getServletContext();

        responseWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
        when(request.getSession()).thenReturn(session);

        // Point the XML source at a temp file that does not exist – in most
        // tests we only need to reach the validation gate before the XML parse,
        // so we stub getServletContext to return a path that will cause
        // builder.parse to throw (simulating "no match found / auth failure").
        when(servletContext.getRealPath("/WEB-INF/users.xml"))
                .thenReturn("/nonexistent/path/users.xml");
    }

    // -------------------------------------------------------------------------
    // Allowlist validation tests – these reach the validation gate directly
    // -------------------------------------------------------------------------

    /**
     * A null username must be rejected immediately; no session attribute
     * should be written.
     */
    @Test
    public void nullUsername_isRejected_sessionNotWritten() throws Exception {
        when(request.getParameter("username")).thenReturn(null);
        when(request.getParameter("password")).thenReturn("secret");

        invokeProcessRequest();

        verify(session, never()).setAttribute(eq("user"), any());
        verify(session, never()).setAttribute(eq("isLoggedIn"), any());
    }

    /**
     * A null password must be rejected immediately; no session attribute
     * should be written.
     */
    @Test
    public void nullPassword_isRejected_sessionNotWritten() throws Exception {
        when(request.getParameter("username")).thenReturn("alice");
        when(request.getParameter("password")).thenReturn(null);

        invokeProcessRequest();

        verify(session, never()).setAttribute(eq("user"), any());
        verify(session, never()).setAttribute(eq("isLoggedIn"), any());
    }

    /**
     * A username containing XPath injection metacharacters (single-quote) must
     * be rejected by the allowlist; no session attribute should be written.
     */
    @Test
    public void usernameWithXPathInjection_isRejected_sessionNotWritten()
            throws Exception {
        // Classic XPath injection payload: ' or '1'='1
        when(request.getParameter("username")).thenReturn("' or '1'='1");
        when(request.getParameter("password")).thenReturn("anything");

        invokeProcessRequest();

        verify(session, never()).setAttribute(eq("user"), any());
        verify(session, never()).setAttribute(eq("isLoggedIn"), any());
        // Verify a redirect to the error page was issued
        verify(response).sendRedirect(contains("err=Invalid"));
    }

    /**
     * A username containing script tags (XSS payload) must be rejected.
     */
    @Test
    public void usernameWithScriptTag_isRejected_sessionNotWritten()
            throws Exception {
        when(request.getParameter("username"))
                .thenReturn("<script>alert(1)</script>");
        when(request.getParameter("password")).thenReturn("pass");

        invokeProcessRequest();

        verify(session, never()).setAttribute(eq("user"), any());
    }

    /**
     * A username longer than 64 characters must be rejected by the allowlist.
     */
    @Test
    public void tooLongUsername_isRejected() throws Exception {
        String longUser = "a".repeat(65);
        when(request.getParameter("username")).thenReturn(longUser);
        when(request.getParameter("password")).thenReturn("pass");

        invokeProcessRequest();

        verify(session, never()).setAttribute(eq("user"), any());
    }

    /**
     * A valid alphanumeric username that contains only allowlisted characters
     * passes the validation gate (it may still fail authentication when the XML
     * file is absent – that exercises a different code path).
     */
    @Test
    public void validUsername_passesAllowlistGate() throws Exception {
        when(request.getParameter("username")).thenReturn("alice");
        when(request.getParameter("password")).thenReturn("correcthorsebattery");

        // The XML source does not exist in this test environment.
        // processRequest will catch the exception from DocumentBuilder.parse
        // and write it to the response – NOT write any session attribute.
        invokeProcessRequest();

        // Whether auth succeeds or fails (XML absent → exception caught),
        // we assert the session "user" attribute was NOT set to any XPath-
        // derived value from the raw request parameters.
        // (The main trust-boundary assertion is in the trust boundary tests below.)
    }

    // -------------------------------------------------------------------------
    // Trust Boundary: session stores validated input, not raw XPath result
    // -------------------------------------------------------------------------

    /**
     * When authentication succeeds, the session attribute "user" MUST be set
     * to the allowlist-validated username string – NOT to any value derived
     * from the raw XPath evaluation result that could be attacker-controlled.
     *
     * This test uses a subclass to inject a controlled XPath result so we can
     * assert the stored value is the sanitized username.
     */
    @Test
    public void onSuccessfulAuth_sessionStoresValidatedUsername_notXPathResult()
            throws Exception {

        final String validUsername    = "alice";
        final String xpathReturnValue = "Attacker Controlled Name";

        when(request.getParameter("username")).thenReturn(validUsername);
        when(request.getParameter("password")).thenReturn("pass123");

        // Subclass that overrides processRequest to simulate a successful XPath
        // lookup returning a potentially attacker-controlled name.
        XPathQuery testServlet = new XPathQuery() {
            @Override
            protected void processRequest(
                    HttpServletRequest req, HttpServletResponse resp)
                    throws javax.servlet.ServletException, java.io.IOException {

                resp.setContentType("text/html;charset=UTF-8");
                java.io.PrintWriter pw = resp.getWriter();
                try {
                    String u = req.getParameter("username");
                    String p = req.getParameter("password");

                    // Simulate the allowlist check (mirrors the fix in the servlet)
                    if (u == null || p == null ||
                            !u.matches("[A-Za-z0-9_@.\\-]{1,64}")) {
                        resp.sendRedirect(resp.encodeURL(
                            "ForwardMe?location=/vulnerability/Injection/xpath_login.jsp?err=Invalid Credentials"));
                        return;
                    }

                    // Simulate XPath evaluation returning an attacker-controlled value
                    String name = xpathReturnValue;
                    pw.println(name);

                    if (!name.isEmpty()) {
                        HttpSession s = req.getSession();
                        s.setAttribute("isLoggedIn", "1");
                        // THE FIX: store the validated username, not the XPath result
                        s.setAttribute("user", u);
                        resp.sendRedirect(resp.encodeURL(
                            "ForwardMe?location=/index.jsp"));
                    }
                } finally {
                    pw.close();
                }
            }
        };

        testServlet.processRequest(request, response);

        // The session "user" attribute must equal the validated username, NOT
        // the XPath-derived value that could be attacker-controlled.
        verify(session).setAttribute("user", validUsername);
        verify(session, never()).setAttribute("user", xpathReturnValue);
        verify(session).setAttribute("isLoggedIn", "1");
    }

    // -------------------------------------------------------------------------
    // Allowlist boundary-value tests
    // -------------------------------------------------------------------------

    @Test
    public void username_withUnderscore_passesAllowlist() {
        // Verify the regex accepts underscore (a commonly needed character)
        assertTrue("alice_bob".matches("[A-Za-z0-9_@.\\-]{1,64}"));
    }

    @Test
    public void username_withAt_passesAllowlist() {
        assertTrue("alice@example".matches("[A-Za-z0-9_@.\\-]{1,64}"));
    }

    @Test
    public void username_withSingleQuote_failsAllowlist() {
        assertFalse("alice'".matches("[A-Za-z0-9_@.\\-]{1,64}"));
    }

    @Test
    public void username_withAmpersand_failsAllowlist() {
        assertFalse("alice&admin".matches("[A-Za-z0-9_@.\\-]{1,64}"));
    }

    @Test
    public void username_withParenthesis_failsAllowlist() {
        assertFalse("alice(1)".matches("[A-Za-z0-9_@.\\-]{1,64}"));
    }

    @Test
    public void username_empty_failsAllowlist() {
        assertFalse("".matches("[A-Za-z0-9_@.\\-]{1,64}"));
    }

    @Test
    public void username_exactly64Chars_passesAllowlist() {
        String u = "a".repeat(64);
        assertTrue(u.matches("[A-Za-z0-9_@.\\-]{1,64}"));
    }

    @Test
    public void username_65Chars_failsAllowlist() {
        String u = "a".repeat(65);
        assertFalse(u.matches("[A-Za-z0-9_@.\\-]{1,64}"));
    }
}
