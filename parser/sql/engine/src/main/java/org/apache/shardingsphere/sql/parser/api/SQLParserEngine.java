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

package org.apache.shardingsphere.sql.parser.api;

import com.github.benmanes.caffeine.cache.LoadingCache;
import org.apache.shardingsphere.infra.util.spi.ShardingSphereServiceLoader;
import org.apache.shardingsphere.sql.parser.core.ParseASTNode;
import org.apache.shardingsphere.sql.parser.core.database.cache.ParseTreeCacheBuilder;
import org.apache.shardingsphere.sql.parser.core.database.parser.SQLParserExecutor;
import org.apache.shardingsphere.sql.rewrite.spi.SQLParseRewriter;

import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

/**
 * SQL parser engine.
 */
public final class SQLParserEngine {
    
    private final SQLParserExecutor sqlParserExecutor;
    
    private final LoadingCache<String, ParseASTNode> parseTreeCache;
    
    private final List<SQLParseRewriter> sqlParseRewriters;
    
    public SQLParserEngine(final String databaseType, final CacheOption cacheOption) {
        sqlParserExecutor = new SQLParserExecutor(databaseType);
        parseTreeCache = ParseTreeCacheBuilder.build(cacheOption, databaseType);
        sqlParseRewriters = loadSQLParseRewriters();
    }
    
    /**
     * Parse SQL.
     *
     * @param sql SQL to be parsed
     * @param useCache whether use cache
     * @return parse AST node
     */
    public ParseASTNode parse(final String sql, final boolean useCache) {
        String rewrittenSQL = rewriteSQL(sql);
        return useCache ? parseTreeCache.get(rewrittenSQL) : sqlParserExecutor.parse(rewrittenSQL);
    }
    
    private List<SQLParseRewriter> loadSQLParseRewriters() {
        Collection<SQLParseRewriter> services = ShardingSphereServiceLoader.getServiceInstances(SQLParseRewriter.class);
        List<SQLParseRewriter> result = new LinkedList<>(services);
        result.sort(Comparator.comparingInt(SQLParseRewriter::getOrder));
        return result;
    }
    
    private String rewriteSQL(final String sql) {
        String result = sql;
        for (SQLParseRewriter each : sqlParseRewriters) {
            if (each.support(result)) {
                String rewritten = each.rewrite(result);
                if (null != rewritten) {
                    result = rewritten;
                }
            }
        }
        return result;
    }
}
