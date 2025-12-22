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
import org.apache.shardingsphere.infra.merge.result.MergedResult;
import org.apache.shardingsphere.infra.metadata.database.ShardingSphereDatabase;

import java.io.InputStream;
import java.io.Reader;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
    
    public EncryptMergedResult(final ShardingSphereDatabase database, final EncryptRule encryptRule, final SelectStatementContext selectStatementContext, final MergedResult mergedResult) {
        this.database = database;
        this.encryptRule = encryptRule;
        this.selectStatementContext = selectStatementContext;
        this.mergedResult = mergedResult;
        this.columnMetas = buildColumnMetas(selectStatementContext);
    }
    
    @Override
    public boolean next() throws SQLException {
        return mergedResult.next();
    }
    
    @Override
    public Object getValue(final int columnIndex, final Class<?> type) throws SQLException {
        ColumnMeta columnMeta = getColumnMeta(columnIndex);
        if (null == columnMeta || !columnMeta.getTableName().isPresent()) {
            return mergedResult.getValue(columnIndex, type);
        }
        Optional<String> tableName = columnMeta.getTableName();
        if (!tableName.isPresent()) {
            return mergedResult.getValue(columnIndex, type);
        }
        if (!encryptRule.findEncryptTable(tableName.get()).map(optional -> optional.isEncryptColumn(columnMeta.getLogicColumnName())).orElse(false)) {
            return mergedResult.getValue(columnIndex, type);
        }
        Object cipherValue = mergedResult.getValue(columnIndex, Object.class);
        String schemaName = getSchemaName();
        EncryptColumn encryptColumn = encryptRule.getEncryptTable(tableName.get()).getEncryptColumn(columnMeta.getLogicColumnName());
        return encryptColumn.getCipher().decrypt(database.getName(), schemaName, tableName.get(), columnMeta.getLogicColumnName(), cipherValue);
    }
    
    private ColumnMeta getColumnMeta(final int columnIndex) {
        if (columnIndex <= 0 || columnIndex > columnMetas.size()) {
            return null;
        }
        return columnMetas.get(columnIndex - 1);
    }
    
    private List<ColumnMeta> buildColumnMetas(final SelectStatementContext statementContext) {
        if (null == statementContext) {
            return Collections.emptyList();
        }
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
