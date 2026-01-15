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
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.*;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.simple.LiteralExpressionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.expr.subquery.SubqueryExpressionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.item.ExpressionProjectionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.dml.item.ProjectionSegment;
import org.apache.shardingsphere.sql.parser.sql.common.segment.generic.table.SimpleTableSegment;
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
    private final String rawSql;
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
        SUPPORTED_COMPARE_OPERATOR.add("IN");
        SUPPORTED_COMPARE_OPERATOR.add("NOT IN");
        
    }
    
    /**
     * Create encrypt conditions from projection expressions.
     *
     * @param selectStatementContext select statement context
     * @param databaseName database name
     * @return encrypt conditions
     */
    //
    public Collection<EncryptCondition> createEncryptConditions(final SelectStatementContext selectStatementContext, final String databaseName) {
        Collection<ExpressionSegment> projectionExpressions = getProjectionExpressions(selectStatementContext);
        if (projectionExpressions.isEmpty()) {
            return new LinkedList<>();
        }
        Collection<EncryptCondition> result = new LinkedList<>();
        for (ExpressionSegment each : projectionExpressions) {
            addEncryptConditions(result, selectStatementContext, each);
        }
        // for (EncryptCondition c : result) {
        // System.out.println("[ENC-PROJ-COND] type=" + c.getClass().getSimpleName()
        // + ", table=" + c.getTableName()
        // + ", column=" + c.getColumnName()
        // + ", range=" + c.getStartIndex() + "~" + c.getStopIndex());
        // }
        return result;
    }
    
    private Collection<ExpressionSegment> getProjectionExpressions(final SelectStatementContext selectStatementContext) {
        
        Collection<ExpressionSegment> result = new LinkedList<>();
        for (ProjectionSegment each : selectStatementContext.getSqlStatement().getProjections().getProjections()) {
            
            if (each instanceof ExpressionProjectionSegment) {
                ExpressionSegment expr = ((ExpressionProjectionSegment) each).getExpr();
                // System.out.println("[ENC-PROJ] topProjectionExpr=" + expr.getClass().getName());
                if (null != expr) {
                    result.add(expr);
                }
            }
        }
        
        return result;
    }
    
    // private void addEncryptConditions(final Collection<EncryptCondition> encryptConditions,
    // final SelectStatementContext selectCtx,
    // final ExpressionSegment expression) {
    // if (expression == null) {
    // return;
    // }
    //
    // // 1) 先递归子表达式（CONCAT 参数、CASE when/then/else、IN 列表、函数参数等）
    // for (ExpressionSegment child : getChildExpressions(expression)) {
    // addEncryptConditions(encryptConditions, selectCtx, child);
    // }
    //
    // // 2) 只有 Binary / In 才可能生成可 rewrite 的 condition
    // if (!(expression instanceof BinaryOperationExpression) && !(expression instanceof InExpression)) {
    // return;
    // }
    //
    // // 3) NULL / NOT NULL 过滤
    // if (!findNotContainsNullLiteralsExpression(expression).isPresent()) {
    // return;
    // }
    //
    // // 4) 找出本表达式涉及的列，定位表名并判断是否加密列
    // Collection<ColumnSegment> cols = ColumnExtractor.extract(expression);
    // if (cols.isEmpty()) {
    // return;
    // }
    //
    // int tableCount = selectCtx.getTablesContext().getTableNames().size();
    //
    // for (ColumnSegment col : cols) {
    // // 多表且没有 owner 的列，跳过（避免误判）
    // if (!col.getOwner().isPresent() && tableCount > 1) {
    // continue;
    // }
    //
    // String tableName = resolveTableNameByOwner(selectCtx, col);
    // if ((tableName == null || tableName.isEmpty()) && tableCount == 1) {
    // tableName = selectCtx.getTablesContext().getTableNames().iterator().next();
    // }
    // if (tableName == null || tableName.isEmpty()) {
    // continue;
    // }
    //
    // Optional<EncryptTable> encryptTable = encryptRule.findEncryptTable(tableName);
    // if (!encryptTable.isPresent() || !encryptTable.get().isEncryptColumn(col.getIdentifier().getValue())) {
    // continue;
    // }
    //
    // // 5) 命中加密列 -> 对 Binary/In 创建 EncryptCondition
    // createEncryptCondition(expression, tableName).ifPresent(encryptConditions::add);
    // }
    // }
    
    private void addEncryptConditions(final Collection<EncryptCondition> encryptConditions,
                                      final SelectStatementContext selectCtx,
                                      final ExpressionSegment expression) {
        addEncryptConditions(encryptConditions, selectCtx, expression, new java.util.HashSet<>());
    }
    
    private void addEncryptConditions(final Collection<EncryptCondition> encryptConditions,
                                      final SelectStatementContext selectCtx,
                                      final ExpressionSegment expression,
                                      final java.util.Set<String> visited) {
        if (expression == null) {
            return;
        }
        
        // ✅ 关键：用 “class + start + stop” 做去重（同一个节点只处理一次）
        String key = expression.getClass().getName() + "@" + expression.getStartIndex() + "~" + expression.getStopIndex();
        if (!visited.add(key)) {
            return;
        }
        
        // 1) 先递归子表达式
        for (ExpressionSegment child : getChildExpressions(expression)) {
            addEncryptConditions(encryptConditions, selectCtx, child, visited);
        }
        
        // 2) CASE / 逻辑运算本身不产出 condition（条件在子节点）
        if (expression instanceof CaseWhenExpression) {
            return;
        }
        if (expression instanceof BinaryOperationExpression
                && LOGICAL_OPERATOR.contains(((BinaryOperationExpression) expression).getOperator())) {
            return;
        }
        
        // 3) NULL / NOT NULL 过滤
        if (!findNotContainsNullLiteralsExpression(expression).isPresent()) {
            return;
        }
        
        // 4) 当前节点尝试生成 condition
        Collection<ColumnSegment> cols = ColumnExtractor.extract(expression);
        if (cols.isEmpty()) {
            return;
        }
        
        int tableCount = selectCtx.getTablesContext().getTableNames().size();
        for (ColumnSegment col : cols) {
            if (!col.getOwner().isPresent() && tableCount > 1) {
                continue;
            }
            
            String tableName = resolveTableNameByOwner(selectCtx, col);
            
            // 单表兜底
            if ((tableName == null || tableName.isEmpty()) && tableCount == 1) {
                tableName = selectCtx.getTablesContext().getTableNames().iterator().next();
            }
            
            if (tableName == null || tableName.isEmpty()) {
                continue;
            }
            
            Optional<EncryptTable> encryptTable = encryptRule.findEncryptTable(tableName);
            boolean isEncCol = encryptTable.isPresent()
                    && encryptTable.get().isEncryptColumn(col.getIdentifier().getValue());
            
            if (isEncCol) {
                createEncryptCondition(expression, tableName).ifPresent(encryptConditions::add);
            }
        }
    }
    
    @SuppressWarnings("unchecked")
    private Collection<ExpressionSegment> getChildExpressions(final ExpressionSegment expr) {
        Collection<ExpressionSegment> result = new LinkedList<>();
        if (expr == null) {
            return result;
        }
        
        // 0) FunctionSegment：CONCAT / LENGTH / IF / etc.
        // 这是你这次的关键：大 SQL 顶层就是 FunctionSegment(CONCAT)
        if (expr instanceof FunctionSegment) {
            FunctionSegment fn = (FunctionSegment) expr;
            Object paramsObj = fn.getParameters(); // 通常是 List<ExpressionSegment>
            
            if (paramsObj instanceof Collection) {
                for (Object o : (Collection<?>) paramsObj) {
                    if (o instanceof ExpressionSegment) {
                        result.add((ExpressionSegment) o);
                    }
                }
            }
            // 继续走下面的反射兜底也可以，但这里已经能解决 90% 场景
        }
        
        // 1) CASE WHEN：显式支持
        if (expr instanceof CaseWhenExpression) {
            CaseWhenExpression c = (CaseWhenExpression) expr;
            if (c.getCaseExpr() != null)
                result.add(c.getCaseExpr());
            result.addAll(c.getWhenExprs());
            result.addAll(c.getThenExprs());
            if (c.getElseExpr() != null)
                result.add(c.getElseExpr());
            debugChildren(expr, result);
            return result;
        }
        
        // 2) Binary：左右
        if (expr instanceof BinaryOperationExpression) {
            BinaryOperationExpression b = (BinaryOperationExpression) expr;
            if (b.getLeft() != null)
                result.add(b.getLeft());
            if (b.getRight() != null)
                result.add(b.getRight());
            debugChildren(expr, result);
            return result;
        }
        
        // 3) IN：left + list + right
        if (expr instanceof InExpression) {
            InExpression in = (InExpression) expr;
            if (in.getLeft() != null)
                result.add(in.getLeft());
            result.addAll(in.getExpressionList());
            if (in.getRight() != null)
                result.add(in.getRight());
            debugChildren(expr, result);
            return result;
        }
        
        // 4) ListExpression：items
        if (expr instanceof ListExpression) {
            result.addAll(((ListExpression) expr).getItems());
            debugChildren(expr, result);
            return result;
        }
        
        // 5) 反射兜底：括号/复杂表达式/函数参数的不同实现
        result.addAll(invokeExprList(expr, "getParameters"));
        result.addAll(invokeExprList(expr, "getParameterExpressions"));
        result.addAll(invokeExprList(expr, "getExpressions"));
        result.addAll(invokeExprList(expr, "getItems"));
        result.addAll(invokeExprList(expr, "getSegments"));
        
        ExpressionSegment one = invokeOneExpr(expr, "getExpr");
        if (one != null)
            result.add(one);
        one = invokeOneExpr(expr, "getExpression");
        if (one != null)
            result.add(one);
        one = invokeOneExpr(expr, "getInnerExpression");
        if (one != null)
            result.add(one);
        
        debugChildren(expr, result);
        return result;
    }
    
    @SuppressWarnings("unchecked")
    private Collection<ExpressionSegment> invokeExprList(final ExpressionSegment expr, final String methodName) {
        try {
            java.lang.reflect.Method m = expr.getClass().getMethod(methodName);
            Object v = m.invoke(expr);
            if (!(v instanceof Collection)) {
                return java.util.Collections.emptyList();
            }
            Collection<?> c = (Collection<?>) v;
            
            java.util.LinkedHashSet<ExpressionSegment> r = new java.util.LinkedHashSet<>();
            for (Object o : c) {
                if (o instanceof ExpressionSegment) {
                    r.add((ExpressionSegment) o);
                }
            }
            return new java.util.LinkedList<>(r);
        } catch (Exception ignored) {
            return java.util.Collections.emptyList();
        }
    }
    
    private ExpressionSegment invokeOneExpr(final ExpressionSegment expr, final String methodName) {
        try {
            java.lang.reflect.Method m = expr.getClass().getMethod(methodName);
            Object v = m.invoke(expr);
            return (v instanceof ExpressionSegment) ? (ExpressionSegment) v : null;
        } catch (Exception ignored) {
            return null;
        }
    }
    
    private void debugChildren(final ExpressionSegment parent, final Collection<ExpressionSegment> children) {
        if (children == null || children.isEmpty()) {
            return;
        }
        List<String> cls = new LinkedList<>();
        for (ExpressionSegment c : children) {
            if (c != null) {
                cls.add(c.getClass().getSimpleName());
            }
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
    
    // private Optional<EncryptCondition> createEncryptCondition(final ExpressionSegment expression, final String tableName) {
    // if (expression instanceof BinaryOperationExpression) {
    // return createBinaryEncryptCondition((BinaryOperationExpression) expression, tableName);
    // }
    // if (expression instanceof InExpression) {
    //// return createInEncryptCondition(tableName, (InExpression) expression, ((InExpression) expression).getRight());
    // return createInEncryptCondition(tableName, (InExpression) expression, rawSql);
    //
    // }
    // return Optional.empty();
    // }
    
    private Optional<EncryptCondition> createEncryptCondition(final ExpressionSegment expression, final String tableName) {
        if (expression instanceof BinaryOperationExpression) {
            return createBinaryEncryptCondition((BinaryOperationExpression) expression, tableName);
        }
        if (expression instanceof InExpression) {
            InExpression in = (InExpression) expression;
            
            // ✅ 强制 debug：看看 IN 节点到底有没有进来、literal 数量是多少
            int litCnt = 0;
            for (ExpressionSegment each : in.getExpressionList()) {
                if (each instanceof LiteralExpressionSegment) {
                    litCnt++;
                }
            }
            // System.out.println("[ENC-IN] table=" + tableName
            // + ", left=" + (in.getLeft() instanceof ColumnSegment
            // ? ((ColumnSegment) in.getLeft()).getExpression()
            // : in.getLeft().getClass().getSimpleName())
            // + ", literalCount=" + litCnt
            // + ", rightClass=" + (in.getRight() == null ? "null" : in.getRight().getClass().getSimpleName())
            // + ", range=" + in.getStartIndex() + "~" + in.getStopIndex());
            
            return createInEncryptCondition(tableName, in, rawSql);
        }
        return Optional.empty();
    }
    
    private Optional<EncryptCondition> createBinaryEncryptCondition(final BinaryOperationExpression expression, final String tableName) {
        String operator = expression.getOperator();
        
        // 1) 过滤逻辑运算
        if (LOGICAL_OPERATOR.contains(operator)) {
            return Optional.empty();
        }
        
        // 2) 只处理支持的比较运算（记得 static block 加 IN/NOT IN）
        if (!SUPPORTED_COMPARE_OPERATOR.contains(operator)) {
            return Optional.empty();
        }
        
        // 3) left 必须是列
        if (!(expression.getLeft() instanceof ColumnSegment)) {
            return Optional.empty();
        }
        if (expression.getRight() instanceof SubqueryExpressionSegment) {
            return Optional.empty();
        }
        
        ColumnSegment col = (ColumnSegment) expression.getLeft();
        String columnName = col.getIdentifier().getValue();
        
        // ✅ A) 处理 IN / NOT IN （很多场景会被解析成 BinaryOperationExpression）
        if ("IN".equalsIgnoreCase(operator) || "NOT IN".equalsIgnoreCase(operator)) {
            if (!(expression.getRight() instanceof ListExpression)) {
                return Optional.empty();
            }
            ListExpression list = (ListExpression) expression.getRight();
            
            List<ExpressionSegment> literalItems = new LinkedList<>();
            for (ExpressionSegment item : list.getItems()) {
                if (item instanceof LiteralExpressionSegment) {
                    literalItems.add(item);
                }
            }
            if (literalItems.isEmpty()) {
                return Optional.empty();
            }
            
            // 用 rawSql 定位括号范围：从 left.stop 往后找 '('，在 expression.stop 范围内找 ')'
            int[] range = findParenRangeForIn(rawSql, col.getStopIndex(), expression.getStopIndex());
            if (range[0] < 0 || range[1] < 0) {
                return Optional.empty();
            }
            
            // System.out.println("[ENC-PROJ-IN-BIN] op=" + operator
            // + ", range=" + range[0] + "~" + range[1]
            // + ", frag=" + rawSql.substring(range[0], Math.min(rawSql.length(), range[1] + 1)));
            
            return Optional.of(new EncryptInCondition(columnName, tableName, range[0], range[1], literalItems));
        }
        
        // ✅ B) 处理 = / LIKE / IS ...（你现在的逻辑：只处理右侧 literal）
        if (!(expression.getRight() instanceof LiteralExpressionSegment)) {
            return Optional.empty();
        }
        
        LiteralExpressionSegment literal = (LiteralExpressionSegment) expression.getRight();
        
        int[] range = findRightLiteralRangeInRawSql(rawSql, expression, literal);
        if (range[0] < 0 || range[1] < 0) {
            return Optional.empty();
        }
        
        // System.out.println("[ENC-PROJ-BIN] op=" + operator + ", range=" + range[0] + "~" + range[1]
        // + ", frag=" + rawSql.substring(range[0], Math.min(rawSql.length(), range[1] + 1)));
        
        return Optional.of(new EncryptBinaryCondition(columnName, tableName, operator, range[0], range[1], literal));
    }
    
    private static int[] findParenRangeForIn(final String rawSql, final int searchFromIdx, final int exprStopIdx) {
        if (rawSql == null || rawSql.isEmpty()) {
            return new int[]{-1, -1};
        }
        int searchFrom = Math.max(0, Math.min(searchFromIdx, rawSql.length() - 1));
        int exprStop = Math.max(0, Math.min(exprStopIdx, rawSql.length() - 1));
        
        int lParen = rawSql.indexOf('(', searchFrom);
        if (lParen < 0 || lParen > exprStop) {
            return new int[]{-1, -1};
        }
        int rParen = rawSql.lastIndexOf(')', exprStop);
        if (rParen < 0 || rParen < lParen) {
            return new int[]{-1, -1};
        }
        return new int[]{lParen, rParen};
    }
    
    /**
     * 在 rawSql 中定位 BinaryOperationExpression 右侧的 literal 真正文本区间（包含引号）。
     * 关键：只在 expression.getStartIndex() ~ expression.getStopIndex() 的窗口里找，避免误命中别的地方。
     */
    private static int[] findRightLiteralRangeInRawSql(final String rawSql,
                                                       final BinaryOperationExpression expression,
                                                       final LiteralExpressionSegment literal) {
        if (rawSql == null || rawSql.isEmpty()) {
            return new int[]{-1, -1};
        }
        
        int winStart = Math.max(0, Math.min(expression.getStartIndex(), rawSql.length() - 1));
        int winEnd = Math.max(0, Math.min(expression.getStopIndex(), rawSql.length() - 1));
        if (winEnd < winStart) {
            return new int[]{-1, -1};
        }
        
        String window = rawSql.substring(winStart, winEnd + 1);
        
        Object litObj = literal.getLiterals();
        if (litObj == null) {
            return new int[]{-1, -1};
        }
        String litVal = String.valueOf(litObj);
        
        // 1) 字符串字面量：优先找 'xxx'
        // 注意：SQL 内部单引号会写成 ''，这里简单做一下 escape
        String needleQuoted = "'" + litVal.replace("'", "''") + "'";
        int idx = window.indexOf(needleQuoted);
        if (idx >= 0) {
            return new int[]{winStart + idx, winStart + idx + needleQuoted.length() - 1};
        }
        
        // 2) 数字 / 布尔 / NULL 等：找一个“边界匹配”的值（避免命中别的数字）
        // 简单边界：前后不是字母数字下划线
        // （不引入 regex 依赖也可以，但这里用一下 regex 更稳）
        String litRegex = "(?i)(^|[^0-9A-Za-z_])" + java.util.regex.Pattern.quote(litVal) + "([^0-9A-Za-z_]|$)";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(litRegex).matcher(window);
        if (m.find()) {
            // group(1) 可能吃掉了一个边界字符，所以要用 m.start(0)/m.end(0) 再缩一下
            int start0 = m.start(0);
            int end0 = m.end(0);
            
            // 在匹配片段里定位 litVal 的真实开始
            int inside = window.substring(start0, end0).toLowerCase().indexOf(litVal.toLowerCase());
            if (inside >= 0) {
                int s = winStart + start0 + inside;
                int e = s + litVal.length() - 1;
                return new int[]{s, e};
            }
        }
        
        return new int[]{-1, -1};
    }
    
    /**
     * Expand literal range to include surrounding single quotes if needed.
     * The parser's start/stop for LiteralExpressionSegment often points to the inner text (without quotes).
     * We use rawSql to safely include quotes so replacement removes the whole `'xxx'`.
     */
    private static int[] calcQuotedLiteralRange(final String rawSql, final int start, final int stop) {
        if (null == rawSql || rawSql.isEmpty()) {
            return new int[]{start, stop};
        }
        int s = Math.max(0, Math.min(start, rawSql.length() - 1));
        int e = Math.max(0, Math.min(stop, rawSql.length() - 1));
        
        // 先尽量把区间扩大到“看起来像一个完整 token”
        // 1) 如果 start-1 是单引号，说明 literal 不含引号 -> 往左扩 1
        if (s - 1 >= 0 && rawSql.charAt(s - 1) == '\'') {
            s = s - 1;
        }
        // 2) 如果 stop+1 是单引号，同理往右扩 1
        if (e + 1 < rawSql.length() && rawSql.charAt(e + 1) == '\'') {
            e = e + 1;
        }
        
        // 兜底：如果我们扩完后左边是引号但右边不是（或反之），再做一次邻近修正
        // 让它尽量覆盖成 `'...something...'`
        if (rawSql.charAt(s) == '\'' && rawSql.charAt(e) != '\'') {
            int r = rawSql.indexOf('\'', s + 1);
            if (r > s) {
                e = r;
            }
        }
        if (rawSql.charAt(e) == '\'' && rawSql.charAt(s) != '\'') {
            int l = rawSql.lastIndexOf('\'', e - 1);
            if (l >= 0) {
                s = l;
            }
        }
        return new int[]{s, e};
    }
    
    // private Optional<EncryptCondition> createBinaryEncryptCondition(final BinaryOperationExpression expression, final String tableName) {
    // String operator = expression.getOperator();
    // if (LOGICAL_OPERATOR.contains(operator)) {
    // return Optional.empty();
    // }
    // if (SUPPORTED_COMPARE_OPERATOR.contains(operator)) {
    // return createCompareEncryptCondition(tableName, expression, expression.getRight());
    // }
    // return Optional.empty();
    // }
    
    // private Optional<EncryptCondition> createCompareEncryptCondition(final String tableName, final BinaryOperationExpression expression, final ExpressionSegment compareRightValue) {
    // if (!(expression.getLeft() instanceof ColumnSegment) || compareRightValue instanceof SubqueryExpressionSegment) {
    // return Optional.empty();
    // }
    // if (compareRightValue instanceof LiteralExpressionSegment) {
    // return Optional.of(createEncryptBinaryOperationCondition(tableName, expression, compareRightValue, compareRightValue));
    // }
    // if (compareRightValue instanceof ListExpression) {
    // ExpressionSegment firstItem = ((ListExpression) compareRightValue).getItems().get(0);
    // if (firstItem instanceof LiteralExpressionSegment) {
    // return Optional.of(createEncryptBinaryOperationCondition(tableName, expression, firstItem, compareRightValue));
    // }
    // }
    // return Optional.empty();
    // }
    private Optional<EncryptCondition> createCompareEncryptCondition(final String tableName,
                                                                     final BinaryOperationExpression expression, final ExpressionSegment compareRightValue) {
        
        if (!(expression.getLeft() instanceof ColumnSegment) || compareRightValue instanceof SubqueryExpressionSegment) {
            return Optional.empty();
        }
        
        // ✅ 1) 先处理 IN / NOT IN（这是你现在缺的）
        String operator = expression.getOperator();
        if ("IN".equalsIgnoreCase(operator) || "NOT IN".equalsIgnoreCase(operator)) {
            if (!(compareRightValue instanceof ListExpression)) {
                return Optional.empty();
            }
            List<ExpressionSegment> literalItems = new LinkedList<>();
            for (ExpressionSegment item : ((ListExpression) compareRightValue).getItems()) {
                if (item instanceof LiteralExpressionSegment) {
                    literalItems.add(item);
                }
            }
            if (literalItems.isEmpty()) {
                return Optional.empty();
            }
            String columnName = ((ColumnSegment) expression.getLeft()).getIdentifier().getValue();
            // 这里 start/stop 用 list 的范围（通常包含括号），用于替换整个 IN (...) 列表
            return Optional.of(new EncryptInCondition(columnName, tableName,
                    compareRightValue.getStartIndex(), compareRightValue.getStopIndex(), literalItems));
        }
        
        // ✅ 2) 原来的 "=" / "LIKE" / "IS" 等逻辑保持不变
        if (compareRightValue instanceof LiteralExpressionSegment) {
            return Optional.of(createEncryptBinaryOperationCondition(tableName, expression, compareRightValue, compareRightValue));
        }
        // if (compareRightValue instanceof ListExpression) {
        // ExpressionSegment firstItem = ((ListExpression) compareRightValue).getItems().get(0);
        // if (firstItem instanceof LiteralExpressionSegment) {
        // return Optional.of(createEncryptBinaryOperationCondition(tableName, expression, firstItem, compareRightValue));
        // }
        // }
        if (compareRightValue instanceof ListExpression) {
            ExpressionSegment firstItem = ((ListExpression) compareRightValue).getItems().get(0);
            if (firstItem instanceof LiteralExpressionSegment) {
                // ✅ 注意：这里只替换 firstItem 的 literal 范围，不要用 compareRightValue 的范围
                return Optional.of(createEncryptBinaryOperationCondition(tableName, expression, firstItem, firstItem));
            }
        }
        
        return Optional.empty();
    }
    // private EncryptBinaryCondition createEncryptBinaryOperationCondition(final String tableName, final BinaryOperationExpression expression,
    // final ExpressionSegment compareRightValue, final ExpressionSegment rightValueSegment) {
    // String columnName = ((ColumnSegment) expression.getLeft()).getIdentifier().getValue();
    // return new EncryptBinaryCondition(columnName, tableName, expression.getOperator(),
    // rightValueSegment.getStartIndex(), rightValueSegment.getStopIndex(), compareRightValue);
    // }
    private EncryptBinaryCondition createEncryptBinaryOperationCondition(final String tableName,
                                                                         final BinaryOperationExpression expression,
                                                                         final ExpressionSegment compareRightValue,
                                                                         final ExpressionSegment rightValueSegment) {
        String columnName = ((ColumnSegment) expression.getLeft()).getIdentifier().getValue();
        
        // ✅ 严格保证替换区间只覆盖 literal 本身，避免吞掉 AND/空格/后续表达式
        int startIndex = rightValueSegment.getStartIndex();
        int stopIndex = rightValueSegment.getStopIndex();
        
        if (compareRightValue instanceof LiteralExpressionSegment) {
            startIndex = compareRightValue.getStartIndex();
            stopIndex = compareRightValue.getStopIndex();
        }
        
        return new EncryptBinaryCondition(columnName, tableName, expression.getOperator(), startIndex, stopIndex, compareRightValue);
    }
    
    private static Optional<EncryptCondition> createInEncryptCondition(final String tableName,
                                                                       final InExpression inExpression,
                                                                       final String rawSql) {
        if (!(inExpression.getLeft() instanceof ColumnSegment) || inExpression.getRight() instanceof SubqueryExpressionSegment) {
            return Optional.empty();
        }
        
        List<ExpressionSegment> literalItems = new LinkedList<>();
        for (ExpressionSegment each : inExpression.getExpressionList()) {
            if (each instanceof LiteralExpressionSegment) {
                literalItems.add(each);
            }
        }
        if (literalItems.isEmpty()) {
            return Optional.empty();
        }
        
        ExpressionSegment right = inExpression.getRight();
        
        // ✅ 只要是 ListExpression，直接用它的范围（不要任何修正）
        if (right instanceof ListExpression) {
            
            int[] range = findInListParenRange(rawSql, inExpression);
            
            if (range[0] < 0) {
                // System.out.println("[ENC-IN-RANGE-FAIL] cannot locate IN (...) range. expr="
                // + safeSub(rawSql, inExpression.getStartIndex(), inExpression.getStopIndex()));
                return Optional.empty();
            }
            
            int startIndex = range[0];
            int stopIndex = range[1];
            String columnName = ((ColumnSegment) inExpression.getLeft()).getIdentifier().getValue();
            // System.out.println("[ENC-PROJ-IN] parenRange=" + startIndex + "~" + stopIndex
            // + ", frag=" + safeSub(rawSql, startIndex, stopIndex));
            return Optional.of(new EncryptInCondition(columnName, tableName, startIndex, stopIndex, literalItems));
        }
        
        return Optional.empty();
    }
    
    private static String safeSub(String s, int start, int stop) {
        if (s == null)
            return "<null>";
        int st = Math.max(0, Math.min(start, s.length()));
        int ed = Math.max(0, Math.min(stop + 1, s.length()));
        if (ed < st)
            return "<bad-range>";
        return s.substring(st, ed);
    }
    
    private static int[] findInListParenRange(final String rawSql, final InExpression inExpr) {
        if (rawSql == null || rawSql.isEmpty())
            return new int[]{-1, -1};
        
        int len = rawSql.length();
        
        // 1) 锚定到当前 InExpression 的 start 附近（最关键）
        int start = clamp(inExpr.getStartIndex(), 0, len - 1);
        
        // 为了更稳：从 start 往前回退一点点（避免 start 落在 "erence_type" 中间）
        int searchFrom = Math.max(0, start - 32);
        
        // 2) 在 [searchFrom .. searchFrom+512] 的小窗口里找 IN / NOT IN
        int winEnd = Math.min(len, searchFrom + 512);
        String win = rawSql.substring(searchFrom, winEnd);
        
        int relInPos = indexOfIgnoreCase(win, "NOT IN");
        int kwLen;
        if (relInPos >= 0) {
            kwLen = "NOT IN".length();
        } else {
            relInPos = indexOfIgnoreCase(win, "IN");
            kwLen = "IN".length();
        }
        if (relInPos < 0)
            return new int[]{-1, -1};
        
        int absInPosAfterKw = searchFrom + relInPos + kwLen;
        
        // 3) 从 IN/NOT IN 后找第一个 '('（允许跨越 inExpr.stopIndex）
        int lParen = rawSql.indexOf('(', absInPosAfterKw);
        if (lParen < 0)
            return new int[]{-1, -1};
        
        // 4) 从 lParen 开始全局括号配对，找到对应 ')'
        int rParen = findMatchingRightParen(rawSql, lParen);
        if (rParen < 0)
            return new int[]{-1, -1};
        // System.out.println("[ENC-IN-RANGE] inExpr=" + inExpr.getStartIndex() + "~" + inExpr.getStopIndex()
        // + ", lParen=" + lParen + ", rParen=" + rParen
        // + ", frag=" + safeSub(rawSql, lParen, rParen));
        return new int[]{lParen, rParen};
    }
    
    private static int findMatchingRightParen(final String sql, final int lParen) {
        int depth = 0;
        boolean inSingle = false;
        boolean inDouble = false;
        
        for (int i = lParen; i < sql.length(); i++) {
            char c = sql.charAt(i);
            
            // 单引号：处理 '' 转义
            if (c == '\'' && !inDouble) {
                if (inSingle && i + 1 < sql.length() && sql.charAt(i + 1) == '\'') {
                    i++;
                    continue;
                }
                inSingle = !inSingle;
                continue;
            }
            
            // 双引号：处理 "" 转义（你这里用的是 "二星"）
            if (c == '"' && !inSingle) {
                if (inDouble && i + 1 < sql.length() && sql.charAt(i + 1) == '"') {
                    i++;
                    continue;
                }
                inDouble = !inDouble;
                continue;
            }
            
            if (inSingle || inDouble)
                continue;
            
            if (c == '(')
                depth++;
            else if (c == ')') {
                depth--;
                if (depth == 0)
                    return i;
            }
        }
        return -1;
    }
    
    private static int indexOfIgnoreCase(String s, String needle) {
        return s.toLowerCase().indexOf(needle.toLowerCase());
    }
    
    private static int clamp(int v, int min, int max) {
        return Math.max(min, Math.min(max, v));
    }
    
    private static int indexOfIgnoreCase(String s, String needle, int fromIndex) {
        String a = s.toLowerCase();
        String b = needle.toLowerCase();
        return a.indexOf(b, Math.max(0, fromIndex));
    }
    
    private static boolean isWordBoundary(String s, int pos, int len) {
        // pos 是 "IN" 的 I 位置，len=2
        int left = pos - 1;
        int right = pos + len;
        
        boolean leftOk = left < 0 || !isWordChar(s.charAt(left));
        boolean rightOk = right >= s.length() || !isWordChar(s.charAt(right));
        return leftOk && rightOk;
    }
    
    private static boolean isWordChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }
    
    private String resolveTableNameByOwner(final SelectStatementContext selectCtx, final ColumnSegment column) {
        if (!column.getOwner().isPresent()) {
            return "";
        }
        String owner = column.getOwner().get().getIdentifier().getValue();
        
        for (SimpleTableSegment each : selectCtx.getTablesContext().getSimpleTableSegments()) {
            String tableName = each.getTableName().getIdentifier().getValue();
            
            // owner 直接是表名
            if (owner.equalsIgnoreCase(tableName)) {
                return tableName;
            }
            
            // owner 是别名
            if (each.getAliasName().isPresent() && owner.equalsIgnoreCase(each.getAliasName().get())) {
                return tableName;
            }
        }
        return "";
    }
    
}
