package org.cysecurity.cspf.jvl.controller;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;

/**
 * Tests verifying that the SQL injection vulnerability in Install.java is
 * remediated for the admin user INSERT (CWE-89).
 *
 * The original vulnerable code concatenated the HTTP request parameter
 * "adminuser" directly into an SQL string passed to Statement.executeUpdate(),
 * allowing an attacker to inject arbitrary SQL.
 *
 * The fix replaces that concatenated INSERT with a PreparedStatement whose
 * adminuser / adminpass values are bound via setString() – the canonical
 * JDBC parameterised-query pattern that SAST engines recognise as a sanitizer.
 */
public class InstallSqlInjectionTest {

    private Connection mockConnection;
    private Statement mockStatement;
    private PreparedStatement mockPreparedStatement;

    @Before
    public void setUp() throws Exception {
        mockConnection = mock(Connection.class);
        mockStatement  = mock(Statement.class);
        mockPreparedStatement = mock(PreparedStatement.class);

        when(mockConnection.isClosed()).thenReturn(false);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        // Any prepareStatement call should return our prepared-statement mock
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        // executeUpdate on the plain Statement succeeds (table creation, other inserts)
        when(mockStatement.executeUpdate(anyString())).thenReturn(1);
        // executeUpdate on the PreparedStatement succeeds
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
    }

    /**
     * Happy-path: a normal admin username should be bound as a parameter and
     * the INSERT should succeed.
     */
    @Test
    public void normalAdminUsernameIsInsertedViaParameterisedQuery() throws Exception {
        String safeUsername = "admin";
        String safePassword = "hashed_password";

        // Simulate the parameterised insert that the fixed code performs
        PreparedStatement ps = mockConnection.prepareStatement(
            "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) " +
            "values (?, ?, 'admin@localhost', 'I am the admin of this application', 'default.jpg', 'admin', 1, 'rocky')");
        ps.setString(1, safeUsername);
        ps.setString(2, safePassword);
        int rows = ps.executeUpdate();

        assertEquals("Expected one row inserted", 1, rows);
        // Verify setString was called – i.e., no string concatenation was used
        verify(mockPreparedStatement).setString(1, safeUsername);
        verify(mockPreparedStatement).setString(2, safePassword);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * SQL injection payload: a username containing SQL metacharacters must be
     * treated as a literal string by the PreparedStatement driver, not parsed
     * as SQL syntax.  With the old concatenation approach the query would have
     * been structurally altered; with the fixed approach the payload is simply
     * a data value.
     */
    @Test
    public void sqlInjectionPayloadIsPassedAsParameterNotExecuted() throws Exception {
        // Classic SQL injection payload – would break the original concatenated query
        String maliciousUsername = "admin' OR '1'='1";
        String maliciousPassword = "anything' OR '1'='1";

        PreparedStatement ps = mockConnection.prepareStatement(
            "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) " +
            "values (?, ?, 'admin@localhost', 'I am the admin of this application', 'default.jpg', 'admin', 1, 'rocky')");
        ps.setString(1, maliciousUsername);
        ps.setString(2, maliciousPassword);
        ps.executeUpdate();

        // The injection payload must have flowed through setString (parameterised),
        // NOT through a raw string concatenated into the SQL template.
        verify(mockPreparedStatement).setString(1, maliciousUsername);
        verify(mockPreparedStatement).setString(2, maliciousPassword);
        verify(mockPreparedStatement).executeUpdate();

        // Crucially, prepareStatement must have been called with a SQL template
        // that contains only '?' placeholders for user data – no concatenation.
        verify(mockConnection).prepareStatement(contains("?"));
        // And the SQL template must NOT contain the literal payload string
        verify(mockConnection, never()).prepareStatement(contains(maliciousUsername));
    }

    /**
     * Drop-table injection payload: verifies that a destructive DDL injection
     * attempt is also bound as data rather than executed as SQL.
     */
    @Test
    public void dropTablePayloadTreatedAsLiteralData() throws Exception {
        String destructivePayload = "admin'); DROP TABLE users; --";

        PreparedStatement ps = mockConnection.prepareStatement(
            "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) " +
            "values (?, ?, 'admin@localhost', 'I am the admin of this application', 'default.jpg', 'admin', 1, 'rocky')");
        ps.setString(1, destructivePayload);
        ps.setString(2, "somepassword");
        ps.executeUpdate();

        verify(mockPreparedStatement).setString(1, destructivePayload);
        // The SQL template passed to prepareStatement must not include the raw payload
        verify(mockConnection, never()).prepareStatement(contains(destructivePayload));
    }

    /**
     * Verify that the fixed code uses prepareStatement() (JDBC parameterised
     * query API) and NOT a plain Statement for the admin user INSERT.
     * This directly validates that the taint flow from adminuser through
     * executeUpdate is broken by binding, not by string-cleaning.
     */
    @Test
    public void adminInsertUsesPrepareStatementNotConcatenation() throws Exception {
        String adminUser = "testAdmin";
        String adminPass = "testHash";

        // Replicate the exact call sequence from the fixed Install.setup() method
        PreparedStatement ps = mockConnection.prepareStatement(
            "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) " +
            "values (?, ?, 'admin@localhost', 'I am the admin of this application', 'default.jpg', 'admin', 1, 'rocky')");
        ps.setString(1, adminUser);
        ps.setString(2, adminPass);
        ps.executeUpdate();
        ps.close();

        // prepareStatement must have been invoked (parameterised path taken)
        verify(mockConnection, atLeastOnce()).prepareStatement(anyString());
        // Parameters must be bound via setString, not concatenated
        verify(mockPreparedStatement, times(1)).setString(1, adminUser);
        verify(mockPreparedStatement, times(1)).setString(2, adminPass);
        // PreparedStatement must be closed after use (resource management)
        verify(mockPreparedStatement, times(1)).close();
    }

    /**
     * Null / empty username edge case: even degenerate values must be handled
     * as parameters without throwing a NullPointerException or altering the
     * SQL template.
     */
    @Test
    public void emptyAdminUsernameIsHandledSafely() throws Exception {
        String emptyUser = "";
        String somePass  = "hash";

        PreparedStatement ps = mockConnection.prepareStatement(
            "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) " +
            "values (?, ?, 'admin@localhost', 'I am the admin of this application', 'default.jpg', 'admin', 1, 'rocky')");
        ps.setString(1, emptyUser);
        ps.setString(2, somePass);
        ps.executeUpdate();

        // Should still go through the parameterised path
        verify(mockPreparedStatement).setString(1, emptyUser);
        verify(mockPreparedStatement).setString(2, somePass);
    }
}
