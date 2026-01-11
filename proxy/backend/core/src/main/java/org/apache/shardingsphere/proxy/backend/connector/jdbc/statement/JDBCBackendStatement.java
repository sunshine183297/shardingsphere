/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shardingsphere.proxy.backend.connector.jdbc.statement;

import org.apache.shardingsphere.db.protocol.parameter.TypeUnspecifiedSQLParameter;
import org.apache.shardingsphere.infra.database.type.DatabaseType;
import org.apache.shardingsphere.infra.executor.sql.context.ExecutionUnit;
import org.apache.shardingsphere.infra.executor.sql.execute.engine.ConnectionMode;
import org.apache.shardingsphere.infra.executor.sql.prepare.driver.jdbc.ExecutorJDBCStatementManager;
import org.apache.shardingsphere.infra.executor.sql.prepare.driver.jdbc.StatementOption;
import org.apache.shardingsphere.infra.util.spi.type.typed.TypedSPILoader;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.Locale;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JDBC backend statement.
 */
public final class JDBCBackendStatement implements ExecutorJDBCStatementManager {
    
    private static final Pattern TABLE_SCHEMA_PATTERN = Pattern.compile("(?i)`?table_schema`?\\s*=\\s*'([^']+)'");
    
    @Override
    public Statement createStorageResource(final Connection connection, final ConnectionMode connectionMode, final StatementOption option, final DatabaseType databaseType) throws SQLException {
        Statement result = connection.createStatement();
        if (ConnectionMode.MEMORY_STRICTLY == connectionMode) {
            setFetchSize(result, databaseType);
        }
        return result;
    }
    
    @Override
    public Statement createStorageResource(final ExecutionUnit executionUnit, final Connection connection, final ConnectionMode connectionMode, final StatementOption option,
                                           final DatabaseType databaseType) throws SQLException {
        String sql = executionUnit.getSqlUnit().getSql();
        List<Object> params = executionUnit.getSqlUnit().getParameters();
        Optional<String> targetCatalog = findTargetCatalog(sql);
        if (targetCatalog.isPresent()) {
            ensureCatalog(connection, targetCatalog.get());
        }
        PreparedStatement result = option.isReturnGeneratedKeys()
                ? connection.prepareStatement(executionUnit.getSqlUnit().getSql(), Statement.RETURN_GENERATED_KEYS)
                : connection.prepareStatement(sql);
        for (int i = 0; i < params.size(); i++) {
            Object param = params.get(i);
            if (param instanceof TypeUnspecifiedSQLParameter) {
                result.setObject(i + 1, param, Types.OTHER);
            } else {
                result.setObject(i + 1, param);
            }
        }
        if (ConnectionMode.MEMORY_STRICTLY == connectionMode) {
            setFetchSize(result, databaseType);
        }
        return result;
    }
    
    private void setFetchSize(final Statement statement, final DatabaseType databaseType) throws SQLException {
        Optional<StatementMemoryStrictlyFetchSizeSetter> fetchSizeSetter = TypedSPILoader.findService(StatementMemoryStrictlyFetchSizeSetter.class, databaseType.getType());
        if (fetchSizeSetter.isPresent()) {
            fetchSizeSetter.get().setFetchSize(statement);
        }
    }
    
    private Optional<String> findTargetCatalog(final String sql) {
        if (null == sql || !sql.toLowerCase(Locale.ENGLISH).contains("information_schema")) {
            return Optional.empty();
        }
        Matcher matcher = TABLE_SCHEMA_PATTERN.matcher(sql);
        if (matcher.find()) {
            return Optional.ofNullable(matcher.group(1));
        }
        return Optional.empty();
    }
    
    private void ensureCatalog(final Connection connection, final String targetCatalog) throws SQLException {
        boolean catalogMatched = false;
        try {
            connection.setCatalog(targetCatalog);
        } catch (final SQLException ignored) {
            // Ignore and fall back to explicit USE statement if needed.
        }
        try {
            String currentCatalog = connection.getCatalog();
            catalogMatched = null != currentCatalog && targetCatalog.equalsIgnoreCase(currentCatalog);
        } catch (final SQLException ignored) {
            // Ignore and fall back to explicit USE statement if needed.
        }
        if (!catalogMatched) {
            try (Statement statement = connection.createStatement()) {
                statement.execute(String.format("USE `%s`", escapeBackticks(targetCatalog)));
            }
        }
    }
    
    private String escapeBackticks(final String value) {
        return value.replace("`", "``");
    }
}
