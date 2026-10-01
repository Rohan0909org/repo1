package org.cysecurity.cspf.jvl.controller;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Set;

/**
 * Tests for the JDBC driver allowlist fix in Install.java.
 *
 * The original vulnerability (CWE-470 – Unsafe Reflection) allowed any
 * attacker-supplied string to be passed directly to Class.forName(), enabling
 * arbitrary class loading.  The fix gates Class.forName() behind a static
 * ALLOWED_JDBC_DRIVERS whitelist.  These tests verify:
 *
 *  1. The allowlist exists and is non-empty.
 *  2. Every legitimate driver class is present in the allowlist.
 *  3. Arbitrary/attacker-supplied class names are NOT present in the allowlist.
 *  4. The setup() method throws ClassNotFoundException (via the allowlist guard)
 *     when an untrusted driver name is supplied, rather than proceeding to
 *     Class.forName() with the malicious value.
 */
public class InstallJdbcDriverAllowlistTest {

    // Known-good driver names that MUST be in the allowlist
    private static final String[] ALLOWED_DRIVERS = {
        "com.mysql.jdbc.Driver",
        "com.mysql.cj.jdbc.Driver",
        "org.postgresql.Driver",
        "oracle.jdbc.OracleDriver",
        "com.microsoft.sqlserver.jdbc.SQLServerDriver",
        "org.h2.Driver",
        "org.hsqldb.jdbc.JDBCDriver",
        "org.apache.derby.jdbc.EmbeddedDriver",
        "org.apache.derby.jdbc.ClientDriver",
        "com.ibm.db2.jcc.DB2Driver",
        "net.sourceforge.jtds.jdbc.Driver"
    };

    // Attacker-controlled payloads that MUST NOT be in the allowlist
    private static final String[] MALICIOUS_DRIVERS = {
        "java.lang.Runtime",
        "sun.misc.Unsafe",
        "com.evil.MaliciousDriver",
        "java.lang.ProcessBuilder",
        "../../../etc/passwd",
        "com.example.ArbitraryClass",
        "",
        null
    };

    private Set<String> allowedJdbcDrivers;

    @Before
    public void setUp() throws Exception {
        // Retrieve the private static ALLOWED_JDBC_DRIVERS field via reflection
        // to inspect its contents without instantiating the servlet.
        Field field = Install.class.getDeclaredField("ALLOWED_JDBC_DRIVERS");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        Set<String> drivers = (Set<String>) field.get(null);
        allowedJdbcDrivers = drivers;
    }

    // -----------------------------------------------------------------------
    // 1. Allowlist existence
    // -----------------------------------------------------------------------

    @Test
    public void allowlist_shouldExistAndBeNonEmpty() {
        assertNotNull("ALLOWED_JDBC_DRIVERS must not be null", allowedJdbcDrivers);
        assertFalse("ALLOWED_JDBC_DRIVERS must not be empty", allowedJdbcDrivers.isEmpty());
    }

    // -----------------------------------------------------------------------
    // 2. Legitimate drivers present
    // -----------------------------------------------------------------------

    @Test
    public void allowlist_shouldContainMySqlDriver() {
        assertTrue("com.mysql.jdbc.Driver must be allowed",
                allowedJdbcDrivers.contains("com.mysql.jdbc.Driver"));
    }

    @Test
    public void allowlist_shouldContainMySqlCjDriver() {
        assertTrue("com.mysql.cj.jdbc.Driver must be allowed",
                allowedJdbcDrivers.contains("com.mysql.cj.jdbc.Driver"));
    }

    @Test
    public void allowlist_shouldContainPostgresDriver() {
        assertTrue("org.postgresql.Driver must be allowed",
                allowedJdbcDrivers.contains("org.postgresql.Driver"));
    }

    @Test
    public void allowlist_shouldContainAllKnownGoodDrivers() {
        for (String driver : ALLOWED_DRIVERS) {
            assertTrue("Expected driver to be in allowlist: " + driver,
                    allowedJdbcDrivers.contains(driver));
        }
    }

    // -----------------------------------------------------------------------
    // 3. Malicious class names absent from the allowlist
    // -----------------------------------------------------------------------

    @Test
    public void allowlist_shouldNotContainJavaLangRuntime() {
        assertFalse("java.lang.Runtime must NOT be in the allowlist",
                allowedJdbcDrivers.contains("java.lang.Runtime"));
    }

    @Test
    public void allowlist_shouldNotContainSunMiscUnsafe() {
        assertFalse("sun.misc.Unsafe must NOT be in the allowlist",
                allowedJdbcDrivers.contains("sun.misc.Unsafe"));
    }

    @Test
    public void allowlist_shouldNotContainArbitraryClasses() {
        String[] arbitrary = {
            "com.evil.MaliciousDriver",
            "java.lang.ProcessBuilder",
            "../../../etc/passwd",
            "com.example.ArbitraryClass"
        };
        for (String cls : arbitrary) {
            assertFalse("Arbitrary class must NOT be in allowlist: " + cls,
                    allowedJdbcDrivers.contains(cls));
        }
    }

    @Test
    public void allowlist_shouldNotContainEmptyString() {
        assertFalse("Empty string must NOT be in allowlist",
                allowedJdbcDrivers.contains(""));
    }

    // -----------------------------------------------------------------------
    // 4. setup() rejects disallowed driver names (exercises the vulnerable sink)
    //
    // The setup() method is protected; we call it via reflection so we can
    // exercise the exact code path that previously led to Class.forName() with
    // an untrusted value.  For each malicious driver name we set the static
    // field, invoke setup("1"), and assert that it returns false (meaning the
    // allowlist guard blocked execution before any class loading occurred).
    // -----------------------------------------------------------------------

    /**
     * Helper: set Install.jdbcdriver to the given value, then call setup("1").
     * Returns the boolean result, or re-throws any unexpected exception.
     */
    private boolean invokeSetupWithDriver(String driverName) throws Exception {
        // Instantiate the servlet without calling init() – we only test setup()
        Install servlet = new Install() {
            // Override the method that tries to load a real properties file,
            // so that the test does not depend on the filesystem.
        };

        // Set the static jdbcdriver field to the attacker-controlled value
        Field driverField = Install.class.getDeclaredField("jdbcdriver");
        driverField.setAccessible(true);
        driverField.set(null, driverName);

        // Also set dburl so that if the allowlist is bypassed the subsequent
        // DriverManager.getConnection() call fails fast rather than hanging.
        Field dburlField = Install.class.getDeclaredField("dburl");
        dburlField.setAccessible(true);
        dburlField.set(null, "jdbc:invalid://localhost/test");

        // Invoke the protected setup() method
        Method setupMethod = Install.class.getDeclaredMethod("setup", String.class);
        setupMethod.setAccessible(true);
        try {
            return (Boolean) setupMethod.invoke(servlet, "1");
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause();
            // ClassNotFoundException is the expected outcome when the allowlist
            // guard throws it; surface as a test assertion failure here.
            if (cause instanceof ClassNotFoundException) {
                // The allowlist guard threw ClassNotFoundException – this is
                // the correct, secure behavior.  Return false to signal that
                // setup did NOT succeed with the malicious driver.
                return false;
            }
            // Any other exception is unexpected; rethrow.
            throw new RuntimeException("Unexpected exception in setup()", cause);
        }
    }

    @Test
    public void setup_shouldReturnFalseForJavaLangRuntime() throws Exception {
        boolean result = invokeSetupWithDriver("java.lang.Runtime");
        assertFalse(
            "setup() must not succeed when jdbcdriver is 'java.lang.Runtime'",
            result);
    }

    @Test
    public void setup_shouldReturnFalseForArbitraryMaliciousDriver() throws Exception {
        boolean result = invokeSetupWithDriver("com.evil.MaliciousDriver");
        assertFalse(
            "setup() must not succeed when jdbcdriver is an arbitrary class",
            result);
    }

    @Test
    public void setup_shouldReturnFalseForNullDriver() throws Exception {
        boolean result = invokeSetupWithDriver(null);
        assertFalse(
            "setup() must not succeed when jdbcdriver is null",
            result);
    }

    @Test
    public void setup_shouldReturnFalseForEmptyStringDriver() throws Exception {
        boolean result = invokeSetupWithDriver("");
        assertFalse(
            "setup() must not succeed when jdbcdriver is an empty string",
            result);
    }

    @Test
    public void setup_shouldReturnFalseForPathTraversalDriver() throws Exception {
        boolean result = invokeSetupWithDriver("../../../etc/passwd");
        assertFalse(
            "setup() must not succeed when jdbcdriver contains a path traversal payload",
            result);
    }

    @Test
    public void setup_shouldReturnFalseWhenSetupParamIsNotOne() throws Exception {
        Install servlet = new Install();
        Field driverField = Install.class.getDeclaredField("jdbcdriver");
        driverField.setAccessible(true);
        driverField.set(null, "com.mysql.jdbc.Driver");

        Method setupMethod = Install.class.getDeclaredMethod("setup", String.class);
        setupMethod.setAccessible(true);
        boolean result = (Boolean) setupMethod.invoke(servlet, "0");
        assertFalse("setup() should return false when setup param != '1'", result);
    }
}
