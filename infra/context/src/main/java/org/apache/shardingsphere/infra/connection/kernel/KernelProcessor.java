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

package org.apache.shardingsphere.infra.connection.kernel;

import org.apache.shardingsphere.infra.config.props.ConfigurationProperties;
import org.apache.shardingsphere.infra.config.props.ConfigurationPropertyKey;
import org.apache.shardingsphere.infra.executor.sql.context.ExecutionContext;
import org.apache.shardingsphere.infra.executor.sql.context.ExecutionContextBuilder;
import org.apache.shardingsphere.infra.executor.sql.log.SQLLogger;
import org.apache.shardingsphere.infra.metadata.ShardingSphereMetaData;
import org.apache.shardingsphere.infra.metadata.database.ShardingSphereDatabase;
import org.apache.shardingsphere.infra.metadata.database.schema.util.SystemSchemaUtils;
import org.apache.shardingsphere.infra.metadata.database.rule.ShardingSphereRuleMetaData;
import org.apache.shardingsphere.infra.rewrite.SQLRewriteEntry;
import org.apache.shardingsphere.infra.rewrite.engine.result.SQLRewriteResult;
import org.apache.shardingsphere.infra.route.context.RouteContext;
import org.apache.shardingsphere.infra.route.engine.SQLRouteEngine;
import org.apache.shardingsphere.infra.session.connection.ConnectionContext;
import org.apache.shardingsphere.infra.session.query.QueryContext;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Kernel processor.
 */
public final class KernelProcessor {
    
    private static final Pattern TABLE_SCHEMA_PATTERN = Pattern.compile("(?i)`?table_schema`?\\s*=\\s*'([^']+)'");
    
    /**
     * Generate execution context.
     *
     * @param queryContext query context
     * @param database database
     * @param metaData meta data
     * @param globalRuleMetaData global rule meta data
     * @param props configuration properties
     * @param connectionContext connection context
     * @return execution context
     */
    public ExecutionContext generateExecutionContext(final QueryContext queryContext, final ShardingSphereDatabase database, final ShardingSphereMetaData metaData,
                                                     final ShardingSphereRuleMetaData globalRuleMetaData,
                                                     final ConfigurationProperties props, final ConnectionContext connectionContext) {
        ShardingSphereDatabase targetDatabase = getTargetDatabase(queryContext, database, metaData);
        RouteContext routeContext = route(queryContext, targetDatabase, globalRuleMetaData, props, connectionContext);
        SQLRewriteResult rewriteResult = rewrite(queryContext, targetDatabase, globalRuleMetaData, props, routeContext, connectionContext);
        ExecutionContext result = createExecutionContext(queryContext, targetDatabase, routeContext, rewriteResult);
        logSQL(queryContext, props, result);
        return result;
    }
    
    private RouteContext route(final QueryContext queryContext, final ShardingSphereDatabase database,
                               final ShardingSphereRuleMetaData globalRuleMetaData, final ConfigurationProperties props, final ConnectionContext connectionContext) {
        return new SQLRouteEngine(database.getRuleMetaData().getRules(), props).route(connectionContext, queryContext, globalRuleMetaData, database);
    }
    
    private SQLRewriteResult rewrite(final QueryContext queryContext, final ShardingSphereDatabase database, final ShardingSphereRuleMetaData globalRuleMetaData,
                                     final ConfigurationProperties props, final RouteContext routeContext, final ConnectionContext connectionContext) {
        SQLRewriteEntry sqlRewriteEntry = new SQLRewriteEntry(database, globalRuleMetaData, props);
        return sqlRewriteEntry.rewrite(queryContext.getSql(), queryContext.getParameters(), queryContext.getSqlStatementContext(), routeContext, connectionContext, queryContext.getHintValueContext());
    }
    
    private ExecutionContext createExecutionContext(final QueryContext queryContext, final ShardingSphereDatabase database, final RouteContext routeContext, final SQLRewriteResult rewriteResult) {
        return new ExecutionContext(queryContext, ExecutionContextBuilder.build(database, rewriteResult, queryContext.getSqlStatementContext()), routeContext);
    }
    
    private void logSQL(final QueryContext queryContext, final ConfigurationProperties props, final ExecutionContext executionContext) {
        if (props.<Boolean>getValue(ConfigurationPropertyKey.SQL_SHOW)) {
            SQLLogger.logSQL(queryContext, props.<Boolean>getValue(ConfigurationPropertyKey.SQL_SIMPLE), executionContext);
        }
    }
    
    private ShardingSphereDatabase getTargetDatabase(final QueryContext queryContext, final ShardingSphereDatabase database, final ShardingSphereMetaData metaData) {
        if (!isInformationSchemaQuery(queryContext, database)) {
            return database;
        }
        Optional<String> tableSchema = findTableSchema(queryContext.getSql());
        if (!tableSchema.isPresent() || !metaData.containsDatabase(tableSchema.get())) {
            return database;
        }
        ShardingSphereDatabase targetDatabase = metaData.getDatabase(tableSchema.get());
        return targetDatabase.containsDataSource() ? targetDatabase : database;
    }
    
    private boolean isInformationSchemaQuery(final QueryContext queryContext, final ShardingSphereDatabase database) {
        if (!SystemSchemaUtils.containsSystemSchema(queryContext.getSqlStatementContext().getDatabaseType(),
                queryContext.getSqlStatementContext().getTablesContext().getSchemaNames(), database)) {
            return false;
        }
        return queryContext.getSql().toLowerCase(Locale.ENGLISH).contains("information_schema");
    }
    
    private Optional<String> findTableSchema(final String sql) {
        if (null == sql) {
            return Optional.empty();
        }
        Matcher matcher = TABLE_SCHEMA_PATTERN.matcher(sql);
        return matcher.find() ? Optional.ofNullable(matcher.group(1)) : Optional.empty();
    }
}
