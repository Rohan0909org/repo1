package org.cysecurity.cspf.jvl.controller;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for the Connection String Injection fix in Install.validateJdbcUrl().
 *
 * The vulnerability: user-supplied "dburl" parameter was passed directly to
 * DriverManager.getConnection() without validation, enabling an attacker to
 * inject arbitrary JDBC connection options (e.g. redirect to a rogue DB,
 * disable SSL, or brute-force credentials via pool-size inflation).
 *
 * The fix: validateJdbcUrl() uses java.net.URI to parse the URL and checks
 * the JDBC sub-protocol against an explicit allowlist {"mysql","postgresql","mariadb"}.
 */
public class InstallValidateJdbcUrlTest {

    // ------------------------------------------------------------------
    // Happy path: URLs that should be accepted
    // ------------------------------------------------------------------

    @Test
    public void mysqlUrlIsAccepted() {
        String url = "jdbc:mysql://localhost:3306/mydb";
        assertEquals(url, Install.validateJdbcUrl(url));
    }

    @Test
    public void postgresqlUrlIsAccepted() {
        String url = "jdbc:postgresql://db.example.com:5432/appdb";
        assertEquals(url, Install.validateJdbcUrl(url));
    }

    @Test
    public void mariadbUrlIsAccepted() {
        String url = "jdbc:mariadb://127.0.0.1/testdb";
        assertEquals(url, Install.validateJdbcUrl(url));
    }

    /** Sub-protocol check must be case-insensitive. */
    @Test
    public void subprotocolCaseInsensitive() {
        String url = "jdbc:MySQL://localhost/db";
        assertEquals(url, Install.validateJdbcUrl(url));
    }

    // ------------------------------------------------------------------
    // Attack vectors: URLs that must be rejected
    // ------------------------------------------------------------------

    /**
     * An attacker attempts to redirect the connection to a rogue server
     * by supplying a non-mysql sub-protocol (e.g. a custom JDBC driver
     * that exfiltrates credentials).
     */
    @Test(expected = IllegalArgumentException.class)
    public void attackerControlledSubprotocolIsRejected() {
        // "rogue" is not in the allowlist
        Install.validateJdbcUrl("jdbc:rogue://attacker.example.com/evildb");
    }

    /**
     * An attacker attempts to inject options by switching the sub-protocol
     * to "sqlserver" which supports extra options like ";integratedSecurity=true".
     */
    @Test(expected = IllegalArgumentException.class)
    public void sqlServerSubprotocolIsRejected() {
        Install.validateJdbcUrl("jdbc:sqlserver://host;integratedSecurity=true");
    }

    /**
     * Injection of Oracle thin driver URL — not in the allowlist.
     */
    @Test(expected = IllegalArgumentException.class)
    public void oracleSubprotocolIsRejected() {
        Install.validateJdbcUrl("jdbc:oracle:thin:@host:1521:orcl");
    }

    /**
     * An attacker omits the "jdbc:" prefix entirely (e.g. passing a plain
     * HTTP URL to redirect to their own endpoint).
     */
    @Test(expected = IllegalArgumentException.class)
    public void missingJdbcPrefixIsRejected() {
        Install.validateJdbcUrl("http://attacker.example.com/steal");
    }

    /**
     * An attacker supplies an empty string as the database URL.
     */
    @Test(expected = IllegalArgumentException.class)
    public void emptyUrlIsRejected() {
        Install.validateJdbcUrl("");
    }

    /**
     * An attacker supplies null as the database URL.
     */
    @Test(expected = IllegalArgumentException.class)
    public void nullUrlIsRejected() {
        Install.validateJdbcUrl(null);
    }

    /**
     * A URL that is syntactically malformed after stripping "jdbc:" must be
     * rejected, not silently accepted or cause an unchecked exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void malformedUrlIsRejected() {
        // Spaces in a URL are a URI syntax error
        Install.validateJdbcUrl("jdbc:mysql://host name/db");
    }

    /**
     * A URL with "jdbc:" prefix only (no sub-protocol) must be rejected.
     */
    @Test(expected = IllegalArgumentException.class)
    public void missingSubprotocolIsRejected() {
        Install.validateJdbcUrl("jdbc://localhost/db");
    }

    // ------------------------------------------------------------------
    // Regression: the returned URL is not modified
    // ------------------------------------------------------------------

    /**
     * Verify that validateJdbcUrl returns the original URL string unchanged,
     * so downstream code receives exactly what the user supplied (after passing
     * the allowlist check).
     */
    @Test
    public void returnedUrlIsUnmodified() {
        String url = "jdbc:mysql://localhost:3306/mydb?useSSL=false";
        String result = Install.validateJdbcUrl(url);
        assertSame("validateJdbcUrl must return the identical String object", url, result);
    }
}
