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

package org.apache.shardingsphere.encrypt.rewrite.context;

import org.apache.shardingsphere.encrypt.api.config.EncryptRuleConfiguration;
import org.apache.shardingsphere.encrypt.api.config.rule.EncryptColumnItemRuleConfiguration;
import org.apache.shardingsphere.encrypt.api.config.rule.EncryptColumnRuleConfiguration;
import org.apache.shardingsphere.encrypt.api.config.rule.EncryptTableRuleConfiguration;
import org.apache.shardingsphere.encrypt.rule.EncryptRule;
import org.apache.shardingsphere.infra.binder.statement.dml.SelectStatementContext;
import org.apache.shardingsphere.infra.config.algorithm.AlgorithmConfiguration;
import org.apache.shardingsphere.infra.config.props.ConfigurationProperties;
import org.apache.shardingsphere.infra.database.DefaultDatabase;
import org.apache.shardingsphere.infra.hint.HintValueContext;
import org.apache.shardingsphere.infra.metadata.ShardingSphereMetaData;
import org.apache.shardingsphere.infra.metadata.database.ShardingSphereDatabase;
import org.apache.shardingsphere.infra.metadata.database.resource.ShardingSphereResourceMetaData;
import org.apache.shardingsphere.infra.metadata.database.rule.ShardingSphereRuleMetaData;
import org.apache.shardingsphere.infra.metadata.database.schema.model.ShardingSphereSchema;
import org.apache.shardingsphere.infra.rewrite.context.SQLRewriteContext;
import org.apache.shardingsphere.infra.rewrite.sql.impl.DefaultSQLBuilder;
import org.apache.shardingsphere.infra.route.context.RouteContext;
import org.apache.shardingsphere.infra.rule.identifier.type.TableContainedRule;
import org.apache.shardingsphere.infra.session.connection.ConnectionContext;
import org.apache.shardingsphere.sql.parser.api.CacheOption;
import org.apache.shardingsphere.sql.parser.api.SQLParserEngine;
import org.apache.shardingsphere.sql.parser.api.SQLStatementVisitorEngine;
import org.apache.shardingsphere.sql.parser.core.ParseASTNode;
import org.apache.shardingsphere.sql.parser.sql.common.statement.SQLStatement;
import org.apache.shardingsphere.sql.parser.sql.common.statement.dml.SelectStatement;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EncryptProjectionRewriteTest {
    
    @Test
    void assertProjectionCaseInExpressionRewrite() {
        String sql = "SELECT e.reference_type, (CASE e.reference_type IN ('二星','三星') WHEN 1 THEN 0 ELSE 5 END) "
                + "FROM ums_member m LEFT JOIN ums_member_extend e ON e.member_id=m.id WHERE m.id = 190856086";
        ShardingSphereSchema schema = createSchema();
        ShardingSphereMetaData metaData = createMetaData(schema);
        SelectStatementContext selectStatementContext = new SelectStatementContext(
                metaData, Collections.emptyList(), (SelectStatement) parseSQL(sql), DefaultDatabase.LOGIC_NAME);
        SQLRewriteContext rewriteContext = new SQLRewriteContext(DefaultDatabase.LOGIC_NAME, Collections.singletonMap(DefaultDatabase.LOGIC_NAME, schema),
                selectStatementContext, sql, Collections.emptyList(), new ConnectionContext(), new HintValueContext());
        new EncryptSQLRewriteContextDecorator().decorate(createEncryptRule(), new ConfigurationProperties(new Properties()), rewriteContext, new RouteContext());
        rewriteContext.generateSQLTokens();
        String rewrittenSql = new DefaultSQLBuilder(rewriteContext).toSQL();
        assertFalse(rewrittenSql.contains("二星"));
        assertFalse(rewrittenSql.contains("三星"));
    }
    
    private SQLStatement parseSQL(final String sql) {
        SQLParserEngine parserEngine = new SQLParserEngine("MySQL", new CacheOption(128, 1024L));
        ParseASTNode parseASTNode = parserEngine.parse(sql, false);
        return new SQLStatementVisitorEngine("MySQL", false).visit(parseASTNode);
    }
    
    private ShardingSphereSchema createSchema() {
        ShardingSphereSchema schema = mock(ShardingSphereSchema.class);
        when(schema.getAllColumnNames("ums_member")).thenReturn(Collections.singletonList("id"));
        when(schema.getAllColumnNames("ums_member_extend")).thenReturn(Arrays.asList("member_id", "reference_type"));
        when(schema.getVisibleColumnNames("ums_member")).thenReturn(Collections.singletonList("id"));
        when(schema.getVisibleColumnNames("ums_member_extend")).thenReturn(Arrays.asList("member_id", "reference_type"));
        return schema;
    }
    
    private ShardingSphereMetaData createMetaData(final ShardingSphereSchema schema) {
        ShardingSphereDatabase database = mock(ShardingSphereDatabase.class, RETURNS_DEEP_STUBS);
        when(database.getSchemas()).thenReturn(Collections.singletonMap(DefaultDatabase.LOGIC_NAME, schema));
        when(database.getRuleMetaData().findRules(TableContainedRule.class)).thenReturn(Collections.emptyList());
        return new ShardingSphereMetaData(Collections.singletonMap(DefaultDatabase.LOGIC_NAME, database), mock(ShardingSphereResourceMetaData.class),
                mock(ShardingSphereRuleMetaData.class), new ConfigurationProperties(new Properties()));
    }
    
    private EncryptRule createEncryptRule() {
        Map<String, AlgorithmConfiguration> encryptors = new LinkedHashMap<>(1, 1F);
        encryptors.put("standard_encryptor", new AlgorithmConfiguration("CORE.FIXTURE", new Properties()));
        EncryptColumnRuleConfiguration columnRuleConfiguration =
                new EncryptColumnRuleConfiguration("reference_type", new EncryptColumnItemRuleConfiguration("reference_type_cipher", "standard_encryptor"));
        EncryptTableRuleConfiguration tableRuleConfiguration = new EncryptTableRuleConfiguration("ums_member_extend", Collections.singleton(columnRuleConfiguration));
        return new EncryptRule(new EncryptRuleConfiguration(Collections.singleton(tableRuleConfiguration), encryptors));
    }
}
