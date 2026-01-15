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

package org.apache.shardingsphere.encrypt.rewrite.condition;

import lombok.RequiredArgsConstructor;
import org.apache.shardingsphere.encrypt.rewrite.condition.impl.EncryptBinaryCondition;
import org.apache.shardingsphere.encrypt.rewrite.condition.impl.EncryptInCondition;
import org.apache.shardingsphere.encrypt.rule.EncryptRule;
import org.apache.shardingsphere.encrypt.rule.EncryptTable;
import org.apache.shardingsphere.infra.binder.statement.dml.SelectStatementContext;
import org.apache.shardingsphere.infra.database.type.DatabaseTypeEngine;
import org.apache.shardingsphere.infra.metadata.database.schema.model.ShardingSphereSchema;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.column.ColumnSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.BinaryOperationExpression;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.CaseWhenExpression;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.ExpressionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.InExpression;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.ListExpression;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.simple.LiteralExpressionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.subquery.SubqueryExpressionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.item.ExpressionProjectionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.item.ProjectionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.util.ColumnExtractor;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Encrypt projection condition engine.
 */
@RequiredArgsConstructor
public final class EncryptProjectionConditionEngine {
    
    private static final Set<String> LOGICAL_OPERATOR = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
    
    private static final Set<String> SUPPORTED_COMPARE_OPERATOR = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
    
    private final EncryptRule encryptRule;
    
    private final Map<String, ShardingSphereSchema> schemas;
    
    static {
        LOGICAL_OPERATOR.add("AND");
        LOGICAL_OPERATOR.add("&&");
        LOGICAL_OPERATOR.add("OR");
        LOGICAL_OPERATOR.add("||");
        SUPPORTED_COMPARE_OPERATOR.add("=");
        SUPPORTED_COMPARE_OPERATOR.add("<>");
        SUPPORTED_COMPARE_OPERATOR.add("!=");
        SUPPORTED_COMPARE_OPERATOR.add(">");
        SUPPORTED_COMPARE_OPERATOR.add("<");
        SUPPORTED_COMPARE_OPERATOR.add(">=");
        SUPPORTED_COMPARE_OPERATOR.add("<=");
        SUPPORTED_COMPARE_OPERATOR.add("IS");
        SUPPORTED_COMPARE_OPERATOR.add("LIKE");
    }
    
    /**
     * Create encrypt conditions from projection expressions.
     *
     * @param selectStatementContext select statement context
     * @param databaseName database name
     * @return encrypt conditions
     */
    public Collection<EncryptCondition> createEncryptConditions(final SelectStatementContext selectStatementContext, final String databaseName) {
        Collection<ExpressionSegment> projectionExpressions = getProjectionExpressions(selectStatementContext);
        if (projectionExpressions.isEmpty()) {
            return new LinkedList<>();
        }
        Collection<ColumnSegment> columnSegments = new LinkedList<>();
        for (ExpressionSegment each : projectionExpressions) {
            columnSegments.addAll(ColumnExtractor.extract(each));
        }
        String defaultSchema = DatabaseTypeEngine.getDefaultSchemaName(selectStatementContext.getDatabaseType(), databaseName);
        ShardingSphereSchema schema = selectStatementContext.getTablesContext().getSchemaName().map(schemas::get).orElseGet(() -> schemas.get(defaultSchema));
        Map<String, String> expressionTableNames = selectStatementContext.getTablesContext().findTableNamesByColumnSegment(columnSegments, schema);
        Collection<EncryptCondition> result = new LinkedList<>();
        for (ExpressionSegment each : projectionExpressions) {
            addEncryptConditions(result, each, expressionTableNames);
        }
        return result;
    }
    
    private Collection<ExpressionSegment> getProjectionExpressions(final SelectStatementContext selectStatementContext) {
        Collection<ExpressionSegment> result = new LinkedList<>();
        for (ProjectionSegment each : selectStatementContext.getSqlStatement().getProjections().getProjections()) {
            if (each instanceof ExpressionProjectionSegment) {
                ExpressionSegment expr = ((ExpressionProjectionSegment) each).getExpr();
                if (null != expr) {
                    result.add(expr);
                }
            }
        }
        return result;
    }
    
    private void addEncryptConditions(final Collection<EncryptCondition> encryptConditions, final ExpressionSegment expression, final Map<String, String> expressionTableNames) {
        if (expression instanceof CaseWhenExpression) {
            addEncryptConditions(encryptConditions, (CaseWhenExpression) expression, expressionTableNames);
            return;
        }
        if (expression instanceof BinaryOperationExpression && LOGICAL_OPERATOR.contains(((BinaryOperationExpression) expression).getOperator())) {
            BinaryOperationExpression binaryExpression = (BinaryOperationExpression) expression;
            addEncryptConditions(encryptConditions, binaryExpression.getLeft(), expressionTableNames);
            addEncryptConditions(encryptConditions, binaryExpression.getRight(), expressionTableNames);
            return;
        }
        if (!findNotContainsNullLiteralsExpression(expression).isPresent()) {
            return;
        }
        for (ColumnSegment each : ColumnExtractor.extract(expression)) {
            if (!each.getOwner().isPresent() && isMultipleTables(expressionTableNames)) {
                continue;
            }
            String tableName = expressionTableNames.getOrDefault(each.getExpression(), "");
            Optional<EncryptTable> encryptTable = encryptRule.findEncryptTable(tableName);
            if (encryptTable.isPresent() && encryptTable.get().isEncryptColumn(each.getIdentifier().getValue())) {
                createEncryptCondition(expression, tableName).ifPresent(encryptConditions::add);
            }
        }
    }
    
    private void addEncryptConditions(final Collection<EncryptCondition> encryptConditions, final CaseWhenExpression expression, final Map<String, String> expressionTableNames) {
        if (null != expression.getCaseExpr()) {
            addEncryptConditions(encryptConditions, expression.getCaseExpr(), expressionTableNames);
        }
        for (ExpressionSegment each : expression.getWhenExprs()) {
            addEncryptConditions(encryptConditions, each, expressionTableNames);
        }
        for (ExpressionSegment each : expression.getThenExprs()) {
            addEncryptConditions(encryptConditions, each, expressionTableNames);
        }
        if (null != expression.getElseExpr()) {
            addEncryptConditions(encryptConditions, expression.getElseExpr(), expressionTableNames);
        }
    }
    
    private boolean isMultipleTables(final Map<String, String> expressionTableNames) {
        return new HashSet<>(expressionTableNames.values()).size() > 1;
    }
    
    private Optional<ExpressionSegment> findNotContainsNullLiteralsExpression(final ExpressionSegment expression) {
        if (isContainsNullLiterals(expression)) {
            return Optional.empty();
        }
        if (expression instanceof BinaryOperationExpression && isContainsNullLiterals(((BinaryOperationExpression) expression).getRight())) {
            return Optional.empty();
        }
        return Optional.ofNullable(expression);
    }
    
    private boolean isContainsNullLiterals(final ExpressionSegment expression) {
        if (!(expression instanceof LiteralExpressionSegment)) {
            return false;
        }
        String literals = String.valueOf(((LiteralExpressionSegment) expression).getLiterals());
        return "NULL".equalsIgnoreCase(literals) || "NOT NULL".equalsIgnoreCase(literals);
    }
    
    private Optional<EncryptCondition> createEncryptCondition(final ExpressionSegment expression, final String tableName) {
        if (expression instanceof BinaryOperationExpression) {
            return createBinaryEncryptCondition((BinaryOperationExpression) expression, tableName);
        }
        if (expression instanceof InExpression) {
            return createInEncryptCondition(tableName, (InExpression) expression, ((InExpression) expression).getRight());
        }
        return Optional.empty();
    }
    
    private Optional<EncryptCondition> createBinaryEncryptCondition(final BinaryOperationExpression expression, final String tableName) {
        String operator = expression.getOperator();
        if (LOGICAL_OPERATOR.contains(operator)) {
            return Optional.empty();
        }
        if (SUPPORTED_COMPARE_OPERATOR.contains(operator)) {
            return createCompareEncryptCondition(tableName, expression, expression.getRight());
        }
        return Optional.empty();
    }
    
    private Optional<EncryptCondition> createCompareEncryptCondition(final String tableName, final BinaryOperationExpression expression, final ExpressionSegment compareRightValue) {
        if (!(expression.getLeft() instanceof ColumnSegment) || compareRightValue instanceof SubqueryExpressionSegment) {
            return Optional.empty();
        }
        if (compareRightValue instanceof LiteralExpressionSegment) {
            return Optional.of(createEncryptBinaryOperationCondition(tableName, expression, compareRightValue, compareRightValue));
        }
        if (compareRightValue instanceof ListExpression) {
            ExpressionSegment firstItem = ((ListExpression) compareRightValue).getItems().get(0);
            if (firstItem instanceof LiteralExpressionSegment) {
                return Optional.of(createEncryptBinaryOperationCondition(tableName, expression, firstItem, compareRightValue));
            }
        }
        return Optional.empty();
    }
    
    private EncryptBinaryCondition createEncryptBinaryOperationCondition(final String tableName, final BinaryOperationExpression expression,
                                                                         final ExpressionSegment compareRightValue, final ExpressionSegment rightValueSegment) {
        String columnName = ((ColumnSegment) expression.getLeft()).getIdentifier().getValue();
        return new EncryptBinaryCondition(columnName, tableName, expression.getOperator(),
                rightValueSegment.getStartIndex(), rightValueSegment.getStopIndex(), compareRightValue);
    }
    
    private static Optional<EncryptCondition> createInEncryptCondition(final String tableName, final InExpression inExpression, final ExpressionSegment inRightValue) {
        if (!(inExpression.getLeft() instanceof ColumnSegment) || inRightValue instanceof SubqueryExpressionSegment) {
            return Optional.empty();
        }
        List<ExpressionSegment> expressionSegments = new LinkedList<>();
        for (ExpressionSegment each : inExpression.getExpressionList()) {
            if (each instanceof LiteralExpressionSegment) {
                expressionSegments.add(each);
            }
        }
        if (expressionSegments.isEmpty()) {
            return Optional.empty();
        }
        String columnName = ((ColumnSegment) inExpression.getLeft()).getIdentifier().getValue();
        return Optional.of(new EncryptInCondition(columnName, tableName, inRightValue.getStartIndex(), inRightValue.getStopIndex(), expressionSegments));
    }
}
