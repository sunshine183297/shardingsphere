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

package org.apache.shardingsphere.encrypt.merge.dql;

import org.apache.shardingsphere.encrypt.rule.EncryptRule;
import org.apache.shardingsphere.encrypt.rule.column.EncryptColumn;
import org.apache.shardingsphere.infra.binder.segment.select.projection.Projection;
import org.apache.shardingsphere.infra.binder.segment.select.projection.impl.ColumnProjection;
import org.apache.shardingsphere.infra.binder.segment.select.projection.impl.ShorthandProjection;
import org.apache.shardingsphere.infra.binder.segment.table.TablesContext;
import org.apache.shardingsphere.infra.binder.statement.dml.SelectStatementContext;
import org.apache.shardingsphere.infra.database.type.DatabaseTypeEngine;
import org.apache.shardingsphere.infra.executor.sql.execute.result.query.QueryResultMetaData;
import org.apache.shardingsphere.infra.merge.result.MergedResult;
import org.apache.shardingsphere.infra.metadata.database.ShardingSphereDatabase;

import java.io.InputStream;
import java.io.Reader;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.Collections;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Merged result for encrypt.
 */
public final class EncryptMergedResult implements MergedResult {
    
    private final ShardingSphereDatabase database;
    
    private final EncryptRule encryptRule;
    
    private final SelectStatementContext selectStatementContext;
    
    private final MergedResult mergedResult;
    
    private final List<ColumnMeta> columnMetas;
    
    private final Map<String, ColumnMeta> columnMetaByLabel;
    
    private final Set<String> conflictColumnLabels = new HashSet<>();
    
    private final QueryResultMetaData queryResultMetaData;

    private final boolean useJdbcMetaDataForColumnMeta;


    public EncryptMergedResult(final ShardingSphereDatabase database, final EncryptRule encryptRule, final SelectStatementContext selectStatementContext, final MergedResult mergedResult) {
        this(database, encryptRule, selectStatementContext, mergedResult, null);
    }
    
    public EncryptMergedResult(final ShardingSphereDatabase database, final EncryptRule encryptRule, final SelectStatementContext selectStatementContext,
                               final MergedResult mergedResult, final QueryResultMetaData queryResultMetaData) {
        this.database = database;
        this.encryptRule = encryptRule;
        this.selectStatementContext = selectStatementContext;
        this.mergedResult = mergedResult;
        this.queryResultMetaData = queryResultMetaData;
        this.useJdbcMetaDataForColumnMeta = null != queryResultMetaData
                && isJoinQuery(selectStatementContext)
                && hasShorthandProjection(selectStatementContext);

        this.columnMetas = buildColumnMetas(selectStatementContext);
        this.columnMetaByLabel = buildColumnMetaByLabelMap(columnMetas);

    }
    
    @Override
    public boolean next() throws SQLException {
        return mergedResult.next();
    }

    @Override
    public Object getValue(final int columnIndex, final Class<?> type) throws SQLException {

//        // 原逻辑
//        ColumnMeta columnMeta = getColumnMeta(columnIndex);
//        if (null == columnMeta || !columnMeta.getTableName().isPresent()) {
//            return mergedResult.getValue(columnIndex, type);
//        }
//
//        Optional<String> tableName = columnMeta.getTableName();
//        if (!encryptRule.findEncryptTable(tableName.get())
//                .map(optional -> optional.isEncryptColumn(columnMeta.getLogicColumnName()))
//                .orElse(false)) {
//            return mergedResult.getValue(columnIndex, type);
//        }
//
//        Object cipherValue = mergedResult.getValue(columnIndex, Object.class);
//        EncryptColumn encryptColumn =
//                encryptRule.getEncryptTable(tableName.get()).getEncryptColumn(columnMeta.getLogicColumnName());
//
//        return encryptColumn.getCipher().decrypt(
//                database.getName(),
//                getSchemaName(),
//                tableName.get(),
//                columnMeta.getLogicColumnName(),
//                cipherValue
//        );
        ColumnMeta columnMeta = getColumnMeta(columnIndex);
        if (null == columnMeta) {
            return mergedResult.getValue(columnIndex, type);
        }

        String logicColumnName = columnMeta.getLogicColumnName();
        if (logicColumnName == null || logicColumnName.isEmpty()) {
            return mergedResult.getValue(columnIndex, type);
        }

        Optional<String> tableName = columnMeta.getTableName();

        // tableName 为空 → 尝试反推
        if (!tableName.isPresent()) {
            tableName = tryInferEncryptTableByColumn(logicColumnName);
        }

        if (!tableName.isPresent()) {
            return mergedResult.getValue(columnIndex, type);
        }

        if (!encryptRule.findEncryptTable(tableName.get())
                .map(t -> t.isEncryptColumn(logicColumnName))
                .orElse(false)) {
            return mergedResult.getValue(columnIndex, type);
        }

        Object cipherValue = mergedResult.getValue(columnIndex, Object.class);
        EncryptColumn encryptColumn =
                encryptRule.getEncryptTable(tableName.get()).getEncryptColumn(logicColumnName);
        System.out.println("[decrypt-hit] col=" + logicColumnName + ", table=" + tableName.get());

        return encryptColumn.getCipher().decrypt(
                database.getName(),
                getSchemaName(),
                tableName.get(),
                logicColumnName,
                cipherValue
        );

    }

    private Optional<String> tryInferEncryptTableByColumn(final String logicColumnName) {
        Collection<String> tableNames = selectStatementContext.getTablesContext().getTableNames();
        String matched = null;
        for (String table : tableNames) {
            if (encryptRule.findEncryptTable(table)
                    .map(t -> t.isEncryptColumn(logicColumnName))
                    .orElse(false)) {
                if (matched != null) {
                    // 多表同名列，放弃解密，避免误解
                    return Optional.empty();
                }
                matched = table;
            }
        }
        return Optional.ofNullable(matched);
    }




    private ColumnMeta getColumnMeta(final int columnIndex) throws SQLException {
        if (null == queryResultMetaData || columnIndex <= 0) {
            return null;
        }
        String columnLabel = queryResultMetaData.getColumnLabel(columnIndex);
        ColumnMeta meta = findColumnMetaByLabel(columnLabel);


        return meta;
    }



    private List<ColumnMeta> buildColumnMetasFromProjections(final SelectStatementContext statementContext) {
        List<Projection> projections = statementContext.getProjectionsContext().getExpandProjections();
        if (projections.isEmpty()) {
            return Collections.emptyList();
        }
        TablesContext tablesContext = statementContext.getTablesContext();
        Collection<String> simpleTableNames = tablesContext.getSimpleTableSegments().stream()
                .map(each -> each.getTableName().getIdentifier().getValue()).collect(Collectors.toList());
        String schemaName = getSchemaName();
        List<ColumnMeta> result = new LinkedList<>();
        for (Projection each : projections) {
            if (each instanceof ColumnProjection) {
                ColumnProjection columnProjection = (ColumnProjection) each;
                String owner = columnProjection.getOwner();
                Optional<String> tableName = resolveTableName(owner, simpleTableNames, tablesContext);
                result.add(new ColumnMeta(tableName, columnProjection.getName(), columnProjection.getColumnLabel()));
                continue;
            }
            if (each instanceof ShorthandProjection) {
                Optional<String> owner = ((ShorthandProjection) each).getOwner();
                Optional<String> tableName = resolveTableName(owner.orElse(null), simpleTableNames, tablesContext);
                if (!tableName.isPresent()) {
                    // Avoid mis-decrypt for owner-less result columns in multi-table join
                    continue;
                }
                Collection<String> columnNames = database.getSchema(schemaName).getAllColumnNames(tableName.get());
                for (String columnName : columnNames) {
                    result.add(new ColumnMeta(tableName, columnName, columnName));
                }
            }
        }
        return result;
    }
    private List<ColumnMeta> buildColumnMetasFromJdbcMetaData() throws SQLException {
        int columnCount = queryResultMetaData.getColumnCount();
        List<ColumnMeta> result = new LinkedList<>();
        for (int i = 1; i <= columnCount; i++) {
            Optional<String> tableName = Optional.ofNullable(emptyToNull(queryResultMetaData.getTableName(i)));

            String columnName = emptyToNull(queryResultMetaData.getColumnName(i));
            String columnLabel = emptyToNull(queryResultMetaData.getColumnLabel(i));

            // ⭐ 核心修复点：表达式列 → 用 label 作为逻辑列名
            String logicColumnName = columnName;
            if (logicColumnName == null || looksLikeExpression(logicColumnName)) {
                logicColumnName = columnLabel;
            }

            result.add(new ColumnMeta(tableName, logicColumnName, columnLabel));
        }
        return result;
    }

    private String emptyToNull(final String s) {
        return (s == null || s.trim().isEmpty()) ? null : s;
    }

    private boolean looksLikeExpression(final String s) {
        // 只要不是纯列名，就认为是表达式
        return !s.matches("^[a-zA-Z0-9_]+$");
    }


    private List<ColumnMeta> buildColumnMetas(final SelectStatementContext statementContext) {
        if (null == statementContext) {
            return Collections.emptyList();
        }
        if (useJdbcMetaDataForColumnMeta) {
            try {
                return buildColumnMetasFromJdbcMetaData();
            } catch (final SQLException ex) {
                // fallback to original behavior if metadata is not available
                return buildColumnMetasFromProjections(statementContext);
            }
        }
        return buildColumnMetasFromProjections(statementContext);
    }


    private Map<String, ColumnMeta> buildColumnMetaByLabelMap(final Collection<ColumnMeta> columnMetas) {
        Map<String, ColumnMeta> result = new HashMap<>(columnMetas.size(), 1F);
        for (ColumnMeta each : columnMetas) {
            String columnLabel = each.getColumnLabel();
            if (null == columnLabel) {
                continue;
            }
            String key = columnLabel.toLowerCase(Locale.ROOT);
            if (result.containsKey(key)) {
                conflictColumnLabels.add(key);
                result.remove(key);
                continue;
            }
            if (conflictColumnLabels.contains(key)) {
                continue;
            }
            result.put(key, each);
        }
        return result;
    }
    
    private ColumnMeta findColumnMetaByLabel(final String columnLabel) {
        if (null == columnLabel) {
            return null;
        }
        String key = columnLabel.toLowerCase(Locale.ROOT);
        return conflictColumnLabels.contains(key) ? null : columnMetaByLabel.get(key);
    }
    
    private Optional<String> resolveTableName(final String owner, final Collection<String> simpleTableNames, final TablesContext tablesContext) {
        if (null != owner) {
            for (org.apache.shardingsphere.sql.parser.sql.common.segment.generic.table.SimpleTableSegment each : tablesContext.getSimpleTableSegments()) {
                Optional<String> alias = each.getAliasName();
                if (alias.isPresent() && alias.get().equalsIgnoreCase(owner)) {
                    return Optional.of(each.getTableName().getIdentifier().getValue());
                }
                if (each.getTableName().getIdentifier().getValue().equalsIgnoreCase(owner)) {
                    return Optional.of(each.getTableName().getIdentifier().getValue());
                }
            }
        }
        if (simpleTableNames.size() == 1) {
            return Optional.of(simpleTableNames.iterator().next());
        }
        return Optional.empty();
    }
    
    private String getSchemaName() {
        return selectStatementContext.getTablesContext().getSchemaName()
                .orElseGet(() -> DatabaseTypeEngine.getDefaultSchemaName(selectStatementContext.getDatabaseType(), database.getName()));
    }

    private boolean isJoinQuery(final SelectStatementContext statementContext) {
        return statementContext.getTablesContext().getSimpleTableSegments().size() > 1;
    }

    private boolean hasShorthandProjection(final SelectStatementContext statementContext) {
        return statementContext.getProjectionsContext().getExpandProjections().stream()
                .anyMatch(each -> each instanceof ShorthandProjection);
    }


    @Override
    public Object getCalendarValue(final int columnIndex, final Class<?> type, final Calendar calendar) throws SQLException {
        return mergedResult.getCalendarValue(columnIndex, type, calendar);
    }
    
    @Override
    public InputStream getInputStream(final int columnIndex, final String type) throws SQLException {
        return mergedResult.getInputStream(columnIndex, type);
    }
    
    @Override
    public Reader getCharacterStream(final int columnIndex) throws SQLException {
        return mergedResult.getCharacterStream(columnIndex);
    }
    
    @Override
    public boolean wasNull() throws SQLException {
        return mergedResult.wasNull();
    }
    
    private static final class ColumnMeta {
        
        private final Optional<String> tableName;
        
        private final String logicColumnName;
        
        private final String columnLabel;
        
        ColumnMeta(final Optional<String> tableName, final String logicColumnName, final String columnLabel) {
            this.tableName = tableName;
            this.logicColumnName = logicColumnName;
            this.columnLabel = columnLabel;
        }
        
        Optional<String> getTableName() {
            return tableName;
        }
        
        String getLogicColumnName() {
            return logicColumnName;
        }
        
        String getColumnLabel() {
            return columnLabel;
        }
    }
}
