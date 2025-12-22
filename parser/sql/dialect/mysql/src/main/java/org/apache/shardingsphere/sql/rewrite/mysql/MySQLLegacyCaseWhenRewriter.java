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

package org.apache.shardingsphere.sql.rewrite.mysql;

import org.apache.shardingsphere.sql.rewrite.spi.SQLParseRewriter;

import java.util.Locale;

/**
 * Legacy CASE WHEN rewriter for MySQL.
 */
public final class MySQLLegacyCaseWhenRewriter implements SQLParseRewriter {
    
    @Override
    public boolean support(final String sql) {
        return null != findNextLegacyCase(sql, 0);
    }
    
    @Override
    public String rewrite(final String sql) {
        if (null == sql) {
            return sql;
        }
        System.out.println(String.format("SQL parse rewrite before: %s", sql));
        StringBuilder rewritten = new StringBuilder(sql.length());
        int cursor = 0;
        LegacyCaseMatch match;
        while (null != (match = findNextLegacyCase(sql, cursor))) {
            rewritten.append(sql, cursor, match.caseStart);
            rewritten.append("CASE WHEN ").append(match.expression).append(" THEN");
            cursor = match.afterThenIndex;
        }
        if (0 == rewritten.length()) {
            System.out.println(String.format("SQL parse rewrite after : %s", sql));
            return sql;
        }
        rewritten.append(sql.substring(cursor));
        String result = rewritten.toString();
        System.out.println(String.format("SQL parse rewrite after : %s", result));
        return result;
    }
    
    private LegacyCaseMatch findNextLegacyCase(final String sql, final int searchStart) {
        if (null == sql || searchStart >= sql.length()) {
            return null;
        }
        String lowerSQL = sql.toLowerCase(Locale.ROOT);
        int index = searchStart;
        while (index < sql.length()) {
            int caseIndex = lowerSQL.indexOf("case", index);
            if (-1 == caseIndex) {
                return null;
            }
            if (!isStandaloneKeyword(lowerSQL, caseIndex, "case")) {
                index = caseIndex + 4;
                continue;
            }
            if (isInsideForbiddenFunction(lowerSQL, caseIndex)) {
                index = caseIndex + 4;
                continue;
            }
            int afterCase = skipWhitespaces(lowerSQL, caseIndex + 4);
            if (afterCase >= sql.length() || '(' != lowerSQL.charAt(afterCase)) {
                index = caseIndex + 4;
                continue;
            }
            int exprStart = afterCase + 1;
            int exprEnd = findMatchingParenthesis(sql, afterCase);
            if (-1 == exprEnd || exprEnd <= exprStart) {
                index = caseIndex + 4;
                continue;
            }
            String expression = sql.substring(exprStart, exprEnd).trim();
            if (expression.isEmpty()) {
                index = caseIndex + 4;
                continue;
            }
            int whenIndex = skipWhitespaces(lowerSQL, exprEnd + 1);
            if (!startsWithKeyword(lowerSQL, whenIndex, "when")) {
                index = caseIndex + 4;
                continue;
            }
            int afterWhen = skipWhitespaces(lowerSQL, whenIndex + 4);
            if (afterWhen >= sql.length() || '1' != lowerSQL.charAt(afterWhen) || isIdentifierChar(afterWhen + 1 < sql.length() ? lowerSQL.charAt(afterWhen + 1) : ' ')) {
                index = caseIndex + 4;
                continue;
            }
            int thenIndex = skipWhitespaces(lowerSQL, afterWhen + 1);
            if (!startsWithKeyword(lowerSQL, thenIndex, "then")) {
                index = caseIndex + 4;
                continue;
            }
            int afterThen = thenIndex + 4;
            return new LegacyCaseMatch(caseIndex, expression, afterThen);
        }
        return null;
    }
    
    private int skipWhitespaces(final String text, final int start) {
        int index = start;
        while (index < text.length() && Character.isWhitespace(text.charAt(index))) {
            index++;
        }
        return index;
    }
    
    private int findMatchingParenthesis(final String sql, final int leftParenthesisIndex) {
        int depth = 0;
        for (int i = leftParenthesisIndex; i < sql.length(); i++) {
            char ch = sql.charAt(i);
            if ('(' == ch) {
                depth++;
            } else if (')' == ch) {
                depth--;
                if (0 == depth) {
                    return i;
                }
            }
        }
        return -1;
    }
    
    private boolean isStandaloneKeyword(final String lowerSQL, final int index, final String keyword) {
        int end = index + keyword.length();
        char before = index - 1 >= 0 ? lowerSQL.charAt(index - 1) : ' ';
        char after = end < lowerSQL.length() ? lowerSQL.charAt(end) : ' ';
        return !isIdentifierChar(before) && !isIdentifierChar(after);
    }
    
    private boolean isIdentifierChar(final char ch) {
        return Character.isLetterOrDigit(ch) || '_' == ch;
    }
    
    private boolean startsWithKeyword(final String lowerSQL, final int index, final String keyword) {
        if (index < 0 || index + keyword.length() > lowerSQL.length()) {
            return false;
        }
        if (!lowerSQL.regionMatches(true, index, keyword, 0, keyword.length())) {
            return false;
        }
        char before = index - 1 >= 0 ? lowerSQL.charAt(index - 1) : ' ';
        char after = index + keyword.length() < lowerSQL.length() ? lowerSQL.charAt(index + keyword.length()) : ' ';
        return !isIdentifierChar(before) && !isIdentifierChar(after);
    }
    
    private boolean isInsideForbiddenFunction(final String lowerSQL, final int caseIndex) {
        int index = caseIndex - 1;
        while (index >= 0 && Character.isWhitespace(lowerSQL.charAt(index))) {
            index--;
        }
        if (index < 0 || '(' != lowerSQL.charAt(index)) {
            return false;
        }
        index--;
        while (index >= 0 && Character.isWhitespace(lowerSQL.charAt(index))) {
            index--;
        }
        if (index < 0) {
            return false;
        }
        int end = index;
        while (index >= 0 && Character.isLetter(lowerSQL.charAt(index))) {
            index--;
        }
        String functionName = lowerSQL.substring(index + 1, end + 1);
        return "concat".equals(functionName) || "if".equals(functionName) || "regexp".equals(functionName);
    }
    
    private static final class LegacyCaseMatch {
        
        private final int caseStart;
        
        private final String expression;
        
        private final int afterThenIndex;
        
        LegacyCaseMatch(final int caseStart, final String expression, final int afterThenIndex) {
            this.caseStart = caseStart;
            this.expression = expression;
            this.afterThenIndex = afterThenIndex;
        }
    }
}
