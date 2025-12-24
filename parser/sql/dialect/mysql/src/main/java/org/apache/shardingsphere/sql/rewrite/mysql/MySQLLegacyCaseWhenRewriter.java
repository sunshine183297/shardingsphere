

package org.apache.shardingsphere.sql.rewrite.mysql;

import org.apache.shardingsphere.sql.rewrite.spi.SQLParseRewriter;

import java.util.Locale;

/**
 * Legacy CASE WHEN rewriter for MySQL.
 */
public final class MySQLLegacyCaseWhenRewriter implements SQLParseRewriter {
    
    @Override
    public boolean support(final String sql) {
        if (sql == null) {
            return false;
        }
        final String lower = sql.toLowerCase(Locale.ROOT);
        return lower.contains("case") && lower.contains("when 1 then");
    }
    
    @Override
    public String rewrite(final String sql) {
        if (sql == null) {
            return null;
        }
        
        final String lower = sql.toLowerCase(Locale.ROOT);
        final StringBuilder out = new StringBuilder(sql.length() + 64);
        
        int cursor = 0;
        boolean changed = false;
        
        while (true) {
            int caseIdx = indexOfStandaloneKeyword(lower, "case", cursor);
            if (caseIdx < 0) {
                out.append(sql.substring(cursor));
                break;
            }
            
            // 输出 case 之前的内容
            out.append(sql, cursor, caseIdx);
            
            int i = caseIdx + 4; // after "case"
            i = skipWs(sql, i);
            
            // 如果是 searched CASE（CASE WHEN ...），跳过不处理
            int whenIdxCandidate = indexOfStandaloneKeyword(lower, "when", i);
            if (whenIdxCandidate == i) {
                // 原样输出 "case"，继续后面
                out.append(sql, caseIdx, i);
                cursor = i;
                continue;
            }
            
            // 解析 expr：从 i 开始，直到遇到本 CASE 头部的 WHEN（且 expr 内部括号/字符串不破坏）
            ExprParseResult expr = parseCaseExpr(sql, lower, i);
            if (!expr.ok) {
                // 解析失败，原样输出 "case"，继续
                out.append(sql, caseIdx, i);
                cursor = i;
                continue;
            }
            
            // expr.whenIndex 是 expr 之后的那个 WHEN 的位置（属于当前 CASE）
            int whenPos = expr.whenIndex;
            int j = whenPos + 4; // after "when"
            j = skipWs(sql, j);
            
            // 必须是 WHEN 1 THEN（允许空白变化）
            if (j >= sql.length() || sql.charAt(j) != '1') {
                // 不是 legacy，原样输出从 caseIdx 到 expr.whenIndex，继续往后
                out.append(sql, caseIdx, whenPos);
                cursor = whenPos;
                continue;
            }
            j++; // after '1'
            // 允许 1 后面紧跟空白
            j = skipWs(sql, j);
            
            int thenPos = indexOfStandaloneKeyword(lower, "then", j);
            if (thenPos != j) {
                // 不是 WHEN 1 THEN（可能 WHEN 10 / WHEN 1.0 / WHEN 1+...），不处理
                out.append(sql, caseIdx, whenPos);
                cursor = whenPos;
                continue;
            }
            
            int afterThen = thenPos + 4;
            
            // ✅ 到这里：确认是 legacy CASE
            // 输出：CASE WHEN <exprText> THEN
            String exprText = expr.exprText.trim();
            exprText = stripOnePairOfOuterParens(exprText); // 可选：去掉最外层括号更稳
            out.append("CASE WHEN ").append(exprText).append(" THEN");
            
            cursor = afterThen;
            changed = true;
        }
        
        final String rewritten = out.toString();
        // if (changed) {
        // System.out.println("====== [SQL PARSE REWRITE] ======");
        // System.out.println("Before:\n" + sql);
        // System.out.println("After:\n" + rewritten);
        // System.out.println("================================");
        // }
        return rewritten;
    }
    
    // ---------------- helpers ----------------
    
    private static int skipWs(final String s, int i) {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
        return i;
    }
    
    /**
     * Find standalone keyword (not part of identifier), case-insensitive (lower already).
     */
    private static int indexOfStandaloneKeyword(final String lower, final String kw, final int from) {
        int idx = lower.indexOf(kw, from);
        while (idx >= 0) {
            if (isKeywordBoundary(lower, idx, kw.length())) {
                return idx;
            }
            idx = lower.indexOf(kw, idx + kw.length());
        }
        return -1;
    }
    
    private static boolean isKeywordBoundary(final String s, final int idx, final int len) {
        char before = idx > 0 ? s.charAt(idx - 1) : ' ';
        char after = (idx + len) < s.length() ? s.charAt(idx + len) : ' ';
        return !isIdent(before) && !isIdent(after);
    }
    
    private static boolean isIdent(final char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '$';
    }
    
    /**
     * Parse expression part of "CASE <expr> WHEN ..."
     * We must stop at the first WHEN that belongs to this CASE header.
     * Must respect:
     *  - parentheses nesting
     *  - single quotes '...'
     *  - double quotes "..."
     *  - backticks `...`
     */
    private static ExprParseResult parseCaseExpr(final String sql, final String lower, final int exprStart) {
        int i = exprStart;
        
        int depth = 0;
        boolean inSingle = false;
        boolean inDouble = false;
        boolean inBacktick = false;
        boolean escaped = false;
        
        while (i < sql.length()) {
            char ch = sql.charAt(i);
            
            // handle escapes inside quotes (MySQL allows \' in some modes; we just keep it safe)
            if ((inSingle || inDouble) && ch == '\\' && !escaped) {
                escaped = true;
                i++;
                continue;
            }
            
            if (!escaped) {
                if (!inDouble && !inBacktick && ch == '\'') {
                    inSingle = !inSingle;
                    i++;
                    continue;
                }
                if (!inSingle && !inBacktick && ch == '"') {
                    inDouble = !inDouble;
                    i++;
                    continue;
                }
                if (!inSingle && !inDouble && ch == '`') {
                    inBacktick = !inBacktick;
                    i++;
                    continue;
                }
            }
            escaped = false;
            
            if (!inSingle && !inDouble && !inBacktick) {
                if (ch == '(') {
                    depth++;
                } else if (ch == ')') {
                    if (depth > 0) {
                        depth--;
                    }
                } else {
                    // only detect WHEN at depth==0 and not in quotes
                    if (depth == 0) {
                        int whenIdx = indexOfStandaloneKeyword(lower, "when", i);
                        if (whenIdx == i) {
                            String exprText = sql.substring(exprStart, whenIdx);
                            return new ExprParseResult(true, exprText, whenIdx);
                        }
                    }
                }
            }
            
            i++;
        }
        
        return new ExprParseResult(false, null, -1);
    }
    
    private static String stripOnePairOfOuterParens(final String expr) {
        String s = expr.trim();
        if (s.length() < 2 || s.charAt(0) != '(' || s.charAt(s.length() - 1) != ')') {
            return s;
        }
        int depth = 0;
        boolean inSingle = false, inDouble = false, inBacktick = false, escaped = false;
        
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            
            if ((inSingle || inDouble) && ch == '\\' && !escaped) {
                escaped = true;
                continue;
            }
            
            if (!escaped) {
                if (!inDouble && !inBacktick && ch == '\'')
                    inSingle = !inSingle;
                else if (!inSingle && !inBacktick && ch == '"')
                    inDouble = !inDouble;
                else if (!inSingle && !inDouble && ch == '`')
                    inBacktick = !inBacktick;
            }
            escaped = false;
            
            if (inSingle || inDouble || inBacktick) {
                continue;
            }
            
            if (ch == '(')
                depth++;
            else if (ch == ')')
                depth--;
            
            // 外括号必须包住整个表达式：只有最后一个字符闭合到 0
            if (depth == 0 && i != s.length() - 1) {
                return s;
            }
        }
        if (depth != 0) {
            return s;
        }
        return s.substring(1, s.length() - 1).trim();
    }
    
    private static final class ExprParseResult {
        
        final boolean ok;
        final String exprText;
        final int whenIndex;
        
        ExprParseResult(final boolean ok, final String exprText, final int whenIndex) {
            this.ok = ok;
            this.exprText = exprText;
            this.whenIndex = whenIndex;
        }
    }
}
