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

package org.apache.shardingsphere.proxy.backend.handler.data.splitter;

import lombok.RequiredArgsConstructor;
import org.apache.shardingsphere.encrypt.rule.EncryptRule;
import org.apache.shardingsphere.infra.binder.SQLStatementContextFactory;
import org.apache.shardingsphere.infra.binder.statement.SQLStatementContext;
import org.apache.shardingsphere.infra.binder.statement.dml.UpdateStatementContext;
import org.apache.shardingsphere.infra.metadata.ShardingSphereMetaData;
import org.apache.shardingsphere.infra.metadata.database.ShardingSphereDatabase;
import org.apache.shardingsphere.infra.session.query.QueryContext;
import org.apache.shardingsphere.parser.rule.SQLParserRule;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.assignment.AssignmentSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.assignment.ColumnAssignmentSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.column.ColumnSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.BetweenExpression;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.BinaryOperationExpression;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.ExpressionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.ExistsSubqueryExpression;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.FunctionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.InExpression;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.ListExpression;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.subquery.SubqueryExpressionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.simple.LiteralExpressionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.simple.ParameterMarkerExpressionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.predicate.WhereSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.generic.table.JoinTableSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.generic.table.SimpleTableSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.generic.table.SubqueryTableSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.generic.table.TableSegment;
import org.apache.shardingsphere.sql.parser.sql.common.statement.SQLStatement;
import org.apache.shardingsphere.sql.parser.sql.dialect.statement.mysql.dml.MySQLUpdateStatement;
import org.apache.shardingsphere.sql.parser.sql.common.util.SQLUtils;
import org.apache.shardingsphere.infra.parser.SQLParserEngine;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Split MySQL multi-table update statements for encrypt rules.
 */
@RequiredArgsConstructor
public final class MultiTableUpdateSplitter {
    
    private final ShardingSphereMetaData metaData;
    
    private final ShardingSphereDatabase database;
    
    private final SQLParserRule sqlParserRule;
    
    /**
     * Split update statement by table when mixed encrypt and non-encrypt tables exist.
     *
     * @param queryContext query context
     * @return query contexts after split
     */
    public Optional<Collection<QueryContext>> split(final QueryContext queryContext) {
        // ===== Feature toggle (default false) =====
        if (!isEnabled()) {
            return Optional.empty();
        }
        
        SQLStatementContext sqlStatementContext = queryContext.getSqlStatementContext();
        if (!(sqlStatementContext instanceof UpdateStatementContext)) {
            return Optional.empty();
        }
        SQLStatement sqlStatement = sqlStatementContext.getSqlStatement();
        if (!(sqlStatement instanceof MySQLUpdateStatement)) {
            return Optional.empty();
        }
        
        MySQLUpdateStatement updateStatement = (MySQLUpdateStatement) sqlStatement;
        if (updateStatement.getOrderBy().isPresent() || updateStatement.getLimit().isPresent()) {
            return Optional.empty();
        }
        
        Optional<EncryptRule> encryptRule = database.getRuleMetaData().findSingleRule(EncryptRule.class);
        if (!encryptRule.isPresent()) {
            return Optional.empty();
        }
        
        List<SimpleTableSegment> updateTables = extractUpdateTables(updateStatement.getTable());
        if (updateTables.size() <= 1) {
            return Optional.empty();
        }
        
        if (!isEncryptMixed(updateTables, encryptRule.get())) {
            return Optional.empty();
        }
        
        Map<String, SimpleTableSegment> aliasToTable = buildAliasToTable(updateTables);
        // ===== Guard: alias duplicated / invalid =====
        if (aliasToTable.isEmpty()) {
            return Optional.empty();
        }
        
        Optional<Map<String, List<AssignmentSegment>>> groupedAssignments =
                groupAssignments(updateStatement.getSetAssignment().getAssignments(), aliasToTable.keySet());
        if (!groupedAssignments.isPresent()) {
            return Optional.empty();
        }
        
        Optional<Map<String, List<BinaryOperationExpression>>> groupedConditions =
                groupWhereConditions(updateStatement.getWhere(), aliasToTable.keySet());
        if (!groupedConditions.isPresent()) {
            return Optional.empty();
        }
        
        // ===== Guard: every table must have assignments =====
        if (!ensureAllTablesAssigned(aliasToTable.keySet(), groupedAssignments.get())) {
            return Optional.empty();
        }
        
        // ===== Guard: prevent FULL TABLE UPDATE after split =====
        // Each table MUST have at least one WHERE predicate after grouping.
        if (!ensureAllTablesHaveConditions(aliasToTable.keySet(), groupedConditions.get())) {
            return Optional.empty();
        }
        
        Collection<QueryContext> result = buildQueryContexts(queryContext, updateTables, groupedAssignments.get(), groupedConditions.get());
        // ===== Guard: buildQueryContexts may return empty if unsafe =====
        return result.isEmpty() ? Optional.empty() : Optional.of(result);
    }
    
    private boolean isEnabled() {
        // Try metaData props first (if available), then system property, default false.
        // try {
        // Properties props = metaData.getProps().getProps();
        // String v = props.getProperty(ENABLE_KEY);
        // if (null != v) {
        // return Boolean.parseBoolean(v);
        // }
        // } catch (Throwable ignored) {
        // // ignore
        // }
        // return Boolean.parseBoolean(System.getProperty(ENABLE_KEY, "false"));
        // todo 增加开关
        
        return true;
    }
    
    private List<SimpleTableSegment> extractUpdateTables(final TableSegment tableSegment) {
        if (tableSegment instanceof SimpleTableSegment) {
            return Collections.singletonList((SimpleTableSegment) tableSegment);
        }
        if (tableSegment instanceof JoinTableSegment) {
            JoinTableSegment joinTableSegment = (JoinTableSegment) tableSegment;
            // Must be comma-style join without ON/USING
            if (null != joinTableSegment.getCondition() || !joinTableSegment.getUsing().isEmpty()) {
                return Collections.emptyList();
            }
            List<SimpleTableSegment> result = new LinkedList<>();
            result.addAll(extractUpdateTables(joinTableSegment.getLeft()));
            result.addAll(extractUpdateTables(joinTableSegment.getRight()));
            return result;
        }
        if (tableSegment instanceof SubqueryTableSegment) {
            return Collections.emptyList();
        }
        return Collections.emptyList();
    }
    
    private boolean isEncryptMixed(final Collection<SimpleTableSegment> tables, final EncryptRule encryptRule) {
        boolean containsEncrypt = false;
        boolean containsPlain = false;
        for (SimpleTableSegment each : tables) {
            String tableName = SQLUtils.getExactlyValue(each.getTableName().getIdentifier().getValue()).toLowerCase();
            if (encryptRule.findEncryptTable(tableName).isPresent()) {
                containsEncrypt = true;
            } else {
                containsPlain = true;
            }
        }
        return containsEncrypt && containsPlain;
    }
    
    private Map<String, SimpleTableSegment> buildAliasToTable(final Collection<SimpleTableSegment> tables) {
        Map<String, SimpleTableSegment> result = new LinkedHashMap<>();
        for (SimpleTableSegment each : tables) {
            String alias = getTableAlias(each);
            if (result.containsKey(alias)) {
                return Collections.emptyMap();
            }
            result.put(alias, each);
        }
        return result;
    }
    
    private Optional<Map<String, List<AssignmentSegment>>> groupAssignments(final Collection<AssignmentSegment> assignments, final Set<String> tableAliases) {
        Map<String, List<AssignmentSegment>> result = new LinkedHashMap<>();
        for (AssignmentSegment each : assignments) {
            if (!(each instanceof ColumnAssignmentSegment)) {
                return Optional.empty();
            }
            ColumnAssignmentSegment assignment = (ColumnAssignmentSegment) each;
            Optional<String> tableAlias = resolveAssignmentTableAlias(assignment, tableAliases);
            if (!tableAlias.isPresent()) {
                return Optional.empty();
            }
            if (!isSupportedAssignmentValue(assignment.getValue(), tableAlias.get())) {
                return Optional.empty();
            }
            result.computeIfAbsent(tableAlias.get(), ignored -> new LinkedList<>()).add(assignment);
        }
        return Optional.of(result);
    }
    
    private Optional<String> resolveAssignmentTableAlias(final ColumnAssignmentSegment assignment, final Set<String> tableAliases) {
        String owner = null;
        for (ColumnSegment column : assignment.getColumns()) {
            if (!column.getOwner().isPresent()) {
                return Optional.empty();
            }
            String columnOwner = column.getOwner().get().getIdentifier().getValue().toLowerCase();
            if (!tableAliases.contains(columnOwner)) {
                return Optional.empty();
            }
            if (null == owner) {
                owner = columnOwner;
            } else if (!owner.equals(columnOwner)) {
                return Optional.empty();
            }
        }
        return Optional.ofNullable(owner);
    }
    
    private Optional<Map<String, List<BinaryOperationExpression>>> groupWhereConditions(final Optional<WhereSegment> whereSegment, final Set<String> tableAliases) {
        if (!whereSegment.isPresent()) {
            // If original SQL has no WHERE, splitting is unsafe (would be full update on every table).
            return Optional.of(new LinkedHashMap<>());
        }
        Optional<List<BinaryOperationExpression>> predicates = extractConjunctionPredicates(whereSegment.get().getExpr());
        if (!predicates.isPresent()) {
            return Optional.empty();
        }
        Map<String, List<BinaryOperationExpression>> result = new LinkedHashMap<>();
        for (BinaryOperationExpression each : predicates.get()) {
            Optional<String> alias = resolveConditionTableAlias(each, tableAliases);
            if (!alias.isPresent()) {
                return Optional.empty();
            }
            result.computeIfAbsent(alias.get(), ignored -> new LinkedList<>()).add(each);
        }
        return Optional.of(result);
    }
    
    private Optional<List<BinaryOperationExpression>> extractConjunctionPredicates(final ExpressionSegment expressionSegment) {
        if (!(expressionSegment instanceof BinaryOperationExpression)) {
            return Optional.empty();
        }
        BinaryOperationExpression binaryExpression = (BinaryOperationExpression) expressionSegment;
        if ("AND".equalsIgnoreCase(binaryExpression.getOperator())) {
            Optional<List<BinaryOperationExpression>> left = extractConjunctionPredicates(binaryExpression.getLeft());
            Optional<List<BinaryOperationExpression>> right = extractConjunctionPredicates(binaryExpression.getRight());
            if (!left.isPresent() || !right.isPresent()) {
                return Optional.empty();
            }
            List<BinaryOperationExpression> result = new LinkedList<>(left.get());
            result.addAll(right.get());
            return Optional.of(result);
        }
        return Optional.of(Collections.singletonList(binaryExpression));
    }
    
    private Optional<String> resolveConditionTableAlias(final BinaryOperationExpression expression, final Set<String> tableAliases) {
        if (!"=".equalsIgnoreCase(expression.getOperator())) {
            return Optional.empty();
        }
        if (expression.getLeft() instanceof ColumnSegment && isLiteralExpression(expression.getRight())) {
            return resolveColumnOwner((ColumnSegment) expression.getLeft(), tableAliases);
        }
        if (expression.getRight() instanceof ColumnSegment && isLiteralExpression(expression.getLeft())) {
            return resolveColumnOwner((ColumnSegment) expression.getRight(), tableAliases);
        }
        return Optional.empty();
    }
    
    private boolean isLiteralExpression(final ExpressionSegment expression) {
        return expression instanceof LiteralExpressionSegment || expression instanceof ParameterMarkerExpressionSegment;
    }
    
    private Optional<String> resolveColumnOwner(final ColumnSegment columnSegment, final Set<String> tableAliases) {
        if (!columnSegment.getOwner().isPresent()) {
            return Optional.empty();
        }
        String owner = columnSegment.getOwner().get().getIdentifier().getValue().toLowerCase();
        return tableAliases.contains(owner) ? Optional.of(owner) : Optional.empty();
    }
    
    private boolean isSupportedAssignmentValue(final ExpressionSegment value, final String tableAlias) {
        if (value instanceof LiteralExpressionSegment || value instanceof ParameterMarkerExpressionSegment) {
            return true;
        }
        if (value instanceof ColumnSegment) {
            return isSameTableColumn((ColumnSegment) value, tableAlias);
        }
        if (value instanceof BinaryOperationExpression) {
            BinaryOperationExpression binary = (BinaryOperationExpression) value;
            return isSupportedAssignmentValue(binary.getLeft(), tableAlias) && isSupportedAssignmentValue(binary.getRight(), tableAlias);
        }
        if (value instanceof BetweenExpression) {
            BetweenExpression between = (BetweenExpression) value;
            return isSupportedAssignmentValue(between.getLeft(), tableAlias)
                    && isSupportedAssignmentValue(between.getBetweenExpr(), tableAlias)
                    && isSupportedAssignmentValue(between.getAndExpr(), tableAlias);
        }
        if (value instanceof InExpression) {
            InExpression inExpression = (InExpression) value;
            return isSupportedAssignmentValue(inExpression.getLeft(), tableAlias) && isSupportedAssignmentValue(inExpression.getRight(), tableAlias);
        }
        if (value instanceof ListExpression) {
            for (ExpressionSegment each : ((ListExpression) value).getItems()) {
                if (!isSupportedAssignmentValue(each, tableAlias)) {
                    return false;
                }
            }
            return true;
        }
        if (value instanceof FunctionSegment) {
            for (ExpressionSegment each : ((FunctionSegment) value).getParameters()) {
                if (!isSupportedAssignmentValue(each, tableAlias)) {
                    return false;
                }
            }
            return true;
        }
        if (value instanceof ExistsSubqueryExpression || value instanceof SubqueryExpressionSegment) {
            return false;
        }
        return false;
    }
    
    private boolean isSameTableColumn(final ColumnSegment columnSegment, final String tableAlias) {
        return columnSegment.getOwner().isPresent()
                && tableAlias.equalsIgnoreCase(columnSegment.getOwner().get().getIdentifier().getValue());
    }
    
    private boolean ensureAllTablesAssigned(final Set<String> tableAliases, final Map<String, List<AssignmentSegment>> assignments) {
        return tableAliases.stream().allMatch(assignments::containsKey);
    }
    
    private boolean ensureAllTablesHaveConditions(final Set<String> tableAliases, final Map<String, List<BinaryOperationExpression>> conditions) {
        // Every table must have at least one predicate, otherwise split may cause full table update.
        for (String alias : tableAliases) {
            List<BinaryOperationExpression> preds = conditions.get(alias);
            if (null == preds || preds.isEmpty()) {
                return false;
            }
        }
        return true;
    }
    
    private Collection<QueryContext> buildQueryContexts(final QueryContext queryContext, final List<SimpleTableSegment> tables,
                                                        final Map<String, List<AssignmentSegment>> assignments,
                                                        final Map<String, List<BinaryOperationExpression>> conditions) {
        Collection<QueryContext> result = new LinkedList<>();
        String originalSql = queryContext.getSql();
        SQLParserEngine sqlParserEngine = sqlParserRule.getSQLParserEngine(database.getProtocolType().getType());
        
        for (SimpleTableSegment eachTable : tables) {
            String tableAlias = getTableAlias(eachTable);
            
            List<AssignmentSegment> tableAssignments = assignments.getOrDefault(tableAlias, Collections.emptyList());
            List<BinaryOperationExpression> tableConditions = conditions.getOrDefault(tableAlias, Collections.emptyList());
            
            // Safety: must not build UPDATE without SET or WHERE
            if (tableAssignments.isEmpty() || tableConditions.isEmpty()) {
                return Collections.emptyList();
            }
            
            String sql = buildUpdateSQL(originalSql, eachTable, tableAssignments, tableConditions);
            
            Optional<List<Object>> parameters = buildParametersSafely(queryContext.getParameters(), tableAssignments, tableConditions);
            if (!parameters.isPresent()) {
                return Collections.emptyList();
            }
            
            SQLStatement newStatement = sqlParserEngine.parse(sql, false);
            SQLStatementContext newStatementContext =
                    SQLStatementContextFactory.newInstance(metaData, parameters.get(), newStatement, database.getName());
            
            result.add(new QueryContext(newStatementContext, sql, parameters.get(),
                    queryContext.getHintValueContext(), queryContext.isUseCache()));
        }
        return result;
    }
    
    private String buildUpdateSQL(final String originalSql, final SimpleTableSegment tableSegment,
                                  final List<AssignmentSegment> assignments, final List<BinaryOperationExpression> conditions) {
        String tableText = extractText(originalSql, tableSegment.getStartIndex(), tableSegment.getStopIndex());
        
        String setText = assignments.stream()
                .sorted(Comparator.comparingInt(AssignmentSegment::getStartIndex))
                .map(each -> extractText(originalSql, each.getStartIndex(), each.getStopIndex()))
                .collect(Collectors.joining(", "));
        
        // setText must not be empty
        if (setText.isEmpty()) {
            return "";
        }
        
        StringBuilder result = new StringBuilder("UPDATE ").append(tableText).append(" SET ").append(setText);
        
        // WHERE must not be empty
        String whereText = conditions.stream()
                .sorted(Comparator.comparingInt(BinaryOperationExpression::getStartIndex))
                .map(each -> extractText(originalSql, each.getStartIndex(), each.getStopIndex()))
                .collect(Collectors.joining(" AND "));
        if (whereText.isEmpty()) {
            return "";
        }
        result.append(" WHERE ").append(whereText);
        
        return result.toString();
    }
    
    private Optional<List<Object>> buildParametersSafely(final List<Object> originParameters,
                                                         final List<AssignmentSegment> assignments,
                                                         final List<BinaryOperationExpression> conditions) {
        List<ParameterMarkerExpressionSegment> markers = new LinkedList<>();
        for (AssignmentSegment each : assignments) {
            collectParameterMarkers(((ColumnAssignmentSegment) each).getValue(), markers);
        }
        for (BinaryOperationExpression each : conditions) {
            collectParameterMarkers(each.getLeft(), markers);
            collectParameterMarkers(each.getRight(), markers);
        }
        
        List<ParameterMarkerExpressionSegment> orderedMarkers = markers.stream()
                .sorted(Comparator.comparingInt(ParameterMarkerExpressionSegment::getStartIndex))
                .collect(Collectors.toList());
        
        List<Object> result = new ArrayList<>(orderedMarkers.size());
        for (ParameterMarkerExpressionSegment each : orderedMarkers) {
            int idx = each.getParameterIndex();
            if (idx < 0 || idx >= originParameters.size()) {
                return Optional.empty();
            }
            result.add(originParameters.get(idx));
        }
        
        // Hard guard: marker count must match parameter count
        if (result.size() != orderedMarkers.size()) {
            return Optional.empty();
        }
        return Optional.of(result);
    }
    
    private void collectParameterMarkers(final ExpressionSegment expressionSegment, final Collection<ParameterMarkerExpressionSegment> collector) {
        if (expressionSegment instanceof ParameterMarkerExpressionSegment) {
            collector.add((ParameterMarkerExpressionSegment) expressionSegment);
            return;
        }
        if (expressionSegment instanceof BinaryOperationExpression) {
            BinaryOperationExpression binary = (BinaryOperationExpression) expressionSegment;
            collectParameterMarkers(binary.getLeft(), collector);
            collectParameterMarkers(binary.getRight(), collector);
            return;
        }
        if (expressionSegment instanceof BetweenExpression) {
            BetweenExpression between = (BetweenExpression) expressionSegment;
            collectParameterMarkers(between.getLeft(), collector);
            collectParameterMarkers(between.getBetweenExpr(), collector);
            collectParameterMarkers(between.getAndExpr(), collector);
            return;
        }
        if (expressionSegment instanceof InExpression) {
            InExpression inExpression = (InExpression) expressionSegment;
            collectParameterMarkers(inExpression.getLeft(), collector);
            collectParameterMarkers(inExpression.getRight(), collector);
            return;
        }
        if (expressionSegment instanceof ListExpression) {
            for (ExpressionSegment each : ((ListExpression) expressionSegment).getItems()) {
                collectParameterMarkers(each, collector);
            }
            return;
        }
        if (expressionSegment instanceof FunctionSegment) {
            for (ExpressionSegment each : ((FunctionSegment) expressionSegment).getParameters()) {
                collectParameterMarkers(each, collector);
            }
        }
    }
    
    private String extractText(final String sql, final int startIndex, final int stopIndex) {
        int safeStart = Math.max(0, startIndex);
        int safeStop = Math.min(sql.length() - 1, stopIndex);
        if (safeStart > safeStop) {
            return "";
        }
        return sql.substring(safeStart, safeStop + 1);
    }
    
    private String getTableAlias(final SimpleTableSegment tableSegment) {
        String alias = tableSegment.getAliasName().orElse(tableSegment.getTableName().getIdentifier().getValue());
        return alias.toLowerCase();
    }
}
