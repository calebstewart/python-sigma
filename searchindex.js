Search.setIndex({docnames:["api/modules","api/sigma","api/sigma.cli","api/sigma.cli.converter","api/sigma.cli.list","api/sigma.cli.mitre","api/sigma.cli.schema","api/sigma.cli.transform","api/sigma.cli.validate","api/sigma.errors","api/sigma.grammar","api/sigma.mitre","api/sigma.schema","api/sigma.serializer","api/sigma.serializer.elastic","api/sigma.transform","api/sigma.util","custom-serializers","custom-transformations","index","serializers/elastic","serializers/index"],envversion:{"sphinx.domains.c":2,"sphinx.domains.changeset":1,"sphinx.domains.citation":1,"sphinx.domains.cpp":5,"sphinx.domains.index":1,"sphinx.domains.javascript":2,"sphinx.domains.math":2,"sphinx.domains.python":3,"sphinx.domains.rst":2,"sphinx.domains.std":2,sphinx:56},filenames:["api/modules.rst","api/sigma.rst","api/sigma.cli.rst","api/sigma.cli.converter.rst","api/sigma.cli.list.rst","api/sigma.cli.mitre.rst","api/sigma.cli.schema.rst","api/sigma.cli.transform.rst","api/sigma.cli.validate.rst","api/sigma.errors.rst","api/sigma.grammar.rst","api/sigma.mitre.rst","api/sigma.schema.rst","api/sigma.serializer.rst","api/sigma.serializer.elastic.rst","api/sigma.transform.rst","api/sigma.util.rst","custom-serializers.rst","custom-transformations.rst","index.rst","serializers/elastic.rst","serializers/index.rst"],objects:{"":[[1,0,0,"-","sigma"]],"sigma.cli":[[2,1,1,"","CommandWithVerbosity"],[2,1,1,"","FuzzyAliasedGroup"],[2,3,1,"","aliased_group"],[3,0,0,"-","converter"],[4,0,0,"-","list"],[5,0,0,"-","mitre"],[6,0,0,"-","schema"],[7,0,0,"-","transform"],[8,0,0,"-","validate"]],"sigma.cli.CommandWithVerbosity":[[2,2,1,"","invoke"]],"sigma.cli.FuzzyAliasedGroup":[[2,2,1,"","command"],[2,2,1,"","get_command"]],"sigma.errors":[[9,4,1,"","ConditionSyntaxError"],[9,4,1,"","DuplicateRuleNameError"],[9,4,1,"","InvalidFieldValueError"],[9,4,1,"","InvalidModifierCombinationError"],[9,4,1,"","MissingCorrelationRule"],[9,4,1,"","MultipleCorrelationError"],[9,4,1,"","NoCorrelationDocument"],[9,4,1,"","RuleValidationError"],[9,4,1,"","SerializerNotFound"],[9,4,1,"","SerializerValidationError"],[9,4,1,"","SigmaError"],[9,4,1,"","SigmaValidationError"],[9,4,1,"","SkipRule"],[9,4,1,"","TransformValidationError"],[9,4,1,"","UnknownIdentifierError"],[9,4,1,"","UnknownModifierError"],[9,4,1,"","UnknownRuleNameError"],[9,4,1,"","UnknownTransform"],[9,4,1,"","UnsupportedFieldComparison"],[9,4,1,"","UnsupportedSerializerFormat"]],"sigma.errors.ConditionSyntaxError":[[9,5,1,"","column"],[9,5,1,"","line"],[9,5,1,"","lineno"],[9,5,1,"","message"]],"sigma.errors.SkipRule":[[9,2,1,"","log"]],"sigma.grammar":[[10,1,1,"","Base64FieldEquality"],[10,1,1,"","CoreExpression"],[10,1,1,"","Expression"],[10,1,1,"","FieldComparison"],[10,1,1,"","FieldContains"],[10,1,1,"","FieldEndsWith"],[10,1,1,"","FieldEquality"],[10,1,1,"","FieldLike"],[10,1,1,"","FieldLookup"],[10,1,1,"","FieldLookupRegex"],[10,1,1,"","FieldNotEmpty"],[10,1,1,"","FieldRegex"],[10,1,1,"","FieldStartsWith"],[10,1,1,"","Identifier"],[10,1,1,"","KeywordSearch"],[10,1,1,"","LogicalAnd"],[10,1,1,"","LogicalExpression"],[10,1,1,"","LogicalNot"],[10,1,1,"","LogicalOr"],[10,1,1,"","Selector"],[10,3,1,"","base64_modifier"],[10,3,1,"","base64offset_modifier"],[10,3,1,"","build_grammar_parser"],[10,3,1,"","build_key_value_expression"],[10,3,1,"","utf16_modifier"],[10,3,1,"","utf16be_modifier"],[10,3,1,"","utf16le_modifier"],[10,3,1,"","wide_modifier"]],"sigma.grammar.Base64FieldEquality":[[10,2,1,"","to_detection"],[10,6,1,"","value"]],"sigma.grammar.CoreExpression":[[10,6,1,"","args"],[10,2,1,"","from_parsed"],[10,2,1,"","postprocess"]],"sigma.grammar.Expression":[[10,6,1,"","operator"],[10,6,1,"","parent"],[10,2,1,"","postprocess"],[10,2,1,"","to_detection"],[10,2,1,"","visit"]],"sigma.grammar.FieldComparison":[[10,6,1,"","field"],[10,2,1,"","to_detection"],[10,2,1,"","to_field_with_modifiers"],[10,6,1,"","value"]],"sigma.grammar.FieldContains":[[10,2,1,"","to_detection"],[10,2,1,"","to_field_with_modifiers"],[10,6,1,"","value"]],"sigma.grammar.FieldEndsWith":[[10,2,1,"","to_detection"],[10,2,1,"","to_field_with_modifiers"],[10,6,1,"","value"]],"sigma.grammar.FieldEquality":[[10,6,1,"","field"],[10,6,1,"","parent"],[10,2,1,"","to_detection"],[10,6,1,"","value"]],"sigma.grammar.FieldLike":[[10,6,1,"","field"],[10,6,1,"","parent"],[10,2,1,"","postprocess"],[10,2,1,"","to_detection"],[10,6,1,"","value"]],"sigma.grammar.FieldLookup":[[10,6,1,"","value"]],"sigma.grammar.FieldLookupRegex":[[10,2,1,"","to_field_with_modifiers"],[10,6,1,"","value"]],"sigma.grammar.FieldNotEmpty":[[10,2,1,"","to_detection"],[10,6,1,"","value"]],"sigma.grammar.FieldRegex":[[10,2,1,"","to_detection"],[10,2,1,"","to_field_with_modifiers"],[10,6,1,"","value"]],"sigma.grammar.FieldStartsWith":[[10,2,1,"","to_detection"],[10,2,1,"","to_field_with_modifiers"],[10,6,1,"","value"]],"sigma.grammar.Identifier":[[10,6,1,"","args"],[10,5,1,"","identifier"],[10,6,1,"","parent"],[10,2,1,"","postprocess"]],"sigma.grammar.KeywordSearch":[[10,2,1,"","to_detection"],[10,6,1,"","value"]],"sigma.grammar.LogicalAnd":[[10,6,1,"","operator"],[10,2,1,"","postprocess"],[10,2,1,"","to_detection"]],"sigma.grammar.LogicalExpression":[[10,6,1,"","operator"],[10,2,1,"","postprocess"]],"sigma.grammar.LogicalNot":[[10,6,1,"","operator"],[10,2,1,"","postprocess"],[10,2,1,"","to_detection"]],"sigma.grammar.LogicalOr":[[10,6,1,"","operator"],[10,2,1,"","postprocess"],[10,2,1,"","to_detection"]],"sigma.grammar.Selector":[[10,6,1,"","args"],[10,5,1,"","condition"],[10,6,1,"","parent"],[10,5,1,"","pattern"],[10,2,1,"","postprocess"]],"sigma.mitre":[[11,1,1,"","Attack"],[11,1,1,"","Tactic"],[11,1,1,"","Technique"]],"sigma.mitre.Attack":[[11,6,1,"","ATTACK_SINGLETON"],[11,6,1,"","ATTACK_URLS"],[11,6,1,"","SOURCE_TYPES"],[11,2,1,"","download"],[11,2,1,"","get_tactic"],[11,2,1,"","get_technique"],[11,2,1,"","load"],[11,6,1,"","tactics"],[11,6,1,"","techniques"]],"sigma.mitre.Tactic":[[11,6,1,"","id"],[11,6,1,"","title"],[11,5,1,"","url"]],"sigma.mitre.Technique":[[11,6,1,"","id"],[11,6,1,"","tactics"],[11,6,1,"","title"],[11,5,1,"","url"]],"sigma.schema":[[12,1,1,"","BaseCorrelation"],[12,1,1,"","Correlation"],[12,1,1,"","CorrelationGreaterThan"],[12,1,1,"","CorrelationGreaterThanEqual"],[12,1,1,"","CorrelationLessThan"],[12,1,1,"","CorrelationLessThanEqual"],[12,1,1,"","CorrelationRange"],[12,1,1,"","CorrelationSimpleCondition"],[12,1,1,"","CorrelationType"],[12,1,1,"","CountCorrelation"],[12,1,1,"","IncludeSchema"],[12,1,1,"","LowercaseString"],[12,1,1,"","Rule"],[12,1,1,"","RuleDetection"],[12,1,1,"","RuleDetectionFields"],[12,1,1,"","RuleDetectionList"],[12,1,1,"","RuleLevel"],[12,1,1,"","RuleLicense"],[12,1,1,"","RuleLogSource"],[12,1,1,"","RuleRelation"],[12,1,1,"","RuleRelationType"],[12,1,1,"","RuleStatus"],[12,1,1,"","RuleTag"],[12,1,1,"","Sigma"],[12,1,1,"","SimpleDate"],[12,1,1,"","TemporalCorrelation"]],"sigma.schema.BaseCorrelation":[[12,6,1,"","action"],[12,6,1,"","group_by"],[12,6,1,"","level"],[12,6,1,"","name"],[12,6,1,"","rule"],[12,6,1,"","timespan"],[12,6,1,"","type"]],"sigma.schema.CorrelationGreaterThan":[[12,6,1,"","gt"]],"sigma.schema.CorrelationGreaterThanEqual":[[12,6,1,"","gte"]],"sigma.schema.CorrelationLessThan":[[12,6,1,"","lt"]],"sigma.schema.CorrelationLessThanEqual":[[12,6,1,"","lte"]],"sigma.schema.CorrelationRange":[[12,5,1,"","maximum"],[12,5,1,"","minimum"],[12,6,1,"","range"]],"sigma.schema.CorrelationSimpleCondition":[[12,5,1,"","value"]],"sigma.schema.CorrelationType":[[12,6,1,"","EVENT_COUNT"],[12,6,1,"","TEMPORAL"],[12,6,1,"","VALUE_COUNT"]],"sigma.schema.CountCorrelation":[[12,6,1,"","condition"],[12,6,1,"","type"]],"sigma.schema.IncludeSchema":[[12,6,1,"","action"],[12,6,1,"","filename"],[12,2,1,"","load"]],"sigma.schema.Rule":[[12,1,1,"","Config"],[12,6,1,"","author"],[12,6,1,"","date"],[12,6,1,"","description"],[12,6,1,"","detection"],[12,6,1,"","falsepositives"],[12,6,1,"","fields"],[12,2,1,"","from_sigma"],[12,2,1,"","from_yaml"],[12,6,1,"","id"],[12,6,1,"","level"],[12,6,1,"","license"],[12,6,1,"","logsource"],[12,6,1,"","modified"],[12,2,1,"","parse_obj"],[12,6,1,"","references"],[12,6,1,"","related"],[12,6,1,"","status"],[12,6,1,"","tags"],[12,6,1,"","title"],[12,2,1,"","to_sigma"],[12,2,1,"","transform"]],"sigma.schema.Rule.Config":[[12,6,1,"","extra"],[12,6,1,"","schema_extra"]],"sigma.schema.RuleDetection":[[12,1,1,"","Config"],[12,6,1,"","GRAMMAR_PARSER"],[12,6,1,"","condition"],[12,5,1,"","expression"],[12,2,1,"","get_expression"],[12,2,1,"","lookup_expression"],[12,2,1,"","parse_grammar"],[12,2,1,"","post_init"],[12,5,1,"","rule"],[12,6,1,"","timeframe"],[12,2,1,"","transform"],[12,2,1,"","update_expression"],[12,2,1,"","validate_detection"]],"sigma.schema.RuleDetection.Config":[[12,6,1,"","extra"],[12,6,1,"","schema_extra"]],"sigma.schema.RuleDetectionFields":[[12,2,1,"","build_expression"]],"sigma.schema.RuleDetectionList":[[12,2,1,"","build_expression"]],"sigma.schema.RuleLevel":[[12,6,1,"","CRITICAL"],[12,6,1,"","HIGH"],[12,6,1,"","INFORMATIONAL"],[12,6,1,"","LOW"],[12,6,1,"","MEDIUM"],[12,2,1,"","to_severity"]],"sigma.schema.RuleLogSource":[[12,1,1,"","Config"],[12,6,1,"","category"],[12,6,1,"","definition"],[12,6,1,"","product"],[12,6,1,"","service"]],"sigma.schema.RuleLogSource.Config":[[12,6,1,"","extra"]],"sigma.schema.RuleRelation":[[12,1,1,"","Config"],[12,6,1,"","id"],[12,6,1,"","type"]],"sigma.schema.RuleRelation.Config":[[12,6,1,"","schema_extra"]],"sigma.schema.RuleRelationType":[[12,6,1,"","DERIVED"],[12,6,1,"","MERGED"],[12,6,1,"","OBSOLETES"],[12,6,1,"","RENAMED"]],"sigma.schema.RuleStatus":[[12,6,1,"","DEPRECATED"],[12,6,1,"","EXPERIMENTAL"],[12,6,1,"","STABLE"],[12,6,1,"","TEST"],[12,6,1,"","TESTING"],[12,6,1,"","UNSUPPORTED"]],"sigma.schema.RuleTag":[[12,5,1,"","name"],[12,5,1,"","namespace"],[12,2,1,"","validate"]],"sigma.schema.Sigma":[[12,2,1,"","load"]],"sigma.schema.TemporalCorrelation":[[12,6,1,"","type"]],"sigma.serializer":[[13,1,1,"","CommonSerializerSchema"],[13,1,1,"","LogSourceMatch"],[13,1,1,"","LogSourceRules"],[13,1,1,"","Serializer"],[13,1,1,"","TextQuerySerializer"],[14,0,0,"-","elastic"],[13,3,1,"","get_builtin_serializers"],[13,3,1,"","get_serializer_class"]],"sigma.serializer.CommonSerializerSchema":[[13,1,1,"","Config"],[13,6,1,"","base"],[13,6,1,"","description"],[13,6,1,"","logsource"],[13,6,1,"","name"],[13,6,1,"","transforms"]],"sigma.serializer.CommonSerializerSchema.Config":[[13,6,1,"","schema_extra"]],"sigma.serializer.LogSourceMatch":[[13,1,1,"","Config"],[13,6,1,"","category"],[13,2,1,"","compare"],[13,6,1,"","conditions"],[13,6,1,"","index"],[13,6,1,"","name"],[13,6,1,"","product"],[13,6,1,"","service"],[13,2,1,"","validate_detection"]],"sigma.serializer.LogSourceMatch.Config":[[13,6,1,"","schema_extra"]],"sigma.serializer.LogSourceRules":[[13,1,1,"","Config"],[13,6,1,"","defaultindex"],[13,2,1,"","match_rule"],[13,6,1,"","merging"],[13,6,1,"","rules"]],"sigma.serializer.LogSourceRules.Config":[[13,6,1,"","schema_extra"]],"sigma.serializer.Serializer":[[13,6,1,"","DEFAULT_FORMAT"],[13,6,1,"","Schema"],[13,2,1,"","apply_rule_transform"],[13,2,1,"","dumps"],[13,2,1,"","from_dict"],[13,2,1,"","from_yaml"],[13,2,1,"","load"],[13,2,1,"","merge_config"],[13,2,1,"","serialize"],[13,2,1,"","transform"]],"sigma.serializer.TextQuerySerializer":[[13,1,1,"","Schema"],[13,2,1,"","dumps"],[13,2,1,"","serialize"],[13,6,1,"","transforms"]],"sigma.serializer.TextQuerySerializer.Schema":[[13,6,1,"","and_format"],[13,6,1,"","bool_false"],[13,6,1,"","bool_true"],[13,6,1,"","escape"],[13,6,1,"","escaped_characters"],[13,6,1,"","field_contains"],[13,6,1,"","field_endswith"],[13,6,1,"","field_equality"],[13,6,1,"","field_like"],[13,6,1,"","field_lookup"],[13,6,1,"","field_lookup_regex"],[13,6,1,"","field_match"],[13,6,1,"","field_not_empty"],[13,6,1,"","field_regex"],[13,6,1,"","field_startswith"],[13,6,1,"","grouping"],[13,6,1,"","keyword"],[13,6,1,"","list_separator"],[13,6,1,"","not_format"],[13,6,1,"","or_format"],[13,6,1,"","quote"]],"sigma.serializer.elastic":[[14,1,1,"","ElasticSecurityActionType"],[14,1,1,"","ElasticSecurityBaseAction"],[14,1,1,"","ElasticSecurityEmailAction"],[14,1,1,"","ElasticSecurityPagerDutyAction"],[14,1,1,"","ElasticSecurityRule"],[14,1,1,"","ElasticSecuritySlackAction"],[14,1,1,"","ElasticSecurityWebhookAction"],[14,1,1,"","EventQueryLanguage"],[14,1,1,"","KibanaQueryLanguage"]],"sigma.serializer.elastic.ElasticSecurityActionType":[[14,6,1,"","EMAIL"],[14,6,1,"","PAGERDUTY"],[14,6,1,"","SLACK"],[14,6,1,"","WEBHOOK"]],"sigma.serializer.elastic.ElasticSecurityBaseAction":[[14,1,1,"","Config"],[14,6,1,"","group"],[14,6,1,"","id"],[14,6,1,"","tags"],[14,2,1,"","to_rule_format"],[14,6,1,"","type"]],"sigma.serializer.elastic.ElasticSecurityBaseAction.Config":[[14,6,1,"","schema_extra"]],"sigma.serializer.elastic.ElasticSecurityEmailAction":[[14,1,1,"","Config"],[14,6,1,"","bcc"],[14,6,1,"","cc"],[14,6,1,"","message"],[14,6,1,"","subject"],[14,6,1,"","to"],[14,2,1,"","to_rule_format"],[14,6,1,"","type"]],"sigma.serializer.elastic.ElasticSecurityEmailAction.Config":[[14,6,1,"","schema_extra"]],"sigma.serializer.elastic.ElasticSecurityPagerDutyAction":[[14,1,1,"","Config"],[14,6,1,"","clazz"],[14,6,1,"","component"],[14,6,1,"","dedup_key"],[14,6,1,"","event_action"],[14,6,1,"","group"],[14,6,1,"","severity"],[14,6,1,"","source"],[14,6,1,"","summary"],[14,6,1,"","timestamp"],[14,2,1,"","to_rule_format"],[14,6,1,"","type"]],"sigma.serializer.elastic.ElasticSecurityPagerDutyAction.Config":[[14,6,1,"","schema_extra"]],"sigma.serializer.elastic.ElasticSecurityRule":[[14,6,1,"","DEFAULT_FORMAT"],[14,1,1,"","Schema"],[14,2,1,"","dumps"],[14,2,1,"","merge_config"],[14,6,1,"","schema"],[14,2,1,"","serialize"]],"sigma.serializer.elastic.ElasticSecurityRule.Schema":[[14,1,1,"","Config"],[14,6,1,"","actions"],[14,6,1,"","enable_rule"],[14,6,1,"","interval"],[14,6,1,"","language"],[14,6,1,"","max_signals"],[14,6,1,"","output_index"],[14,6,1,"","risk_default"],[14,6,1,"","risk_map"],[14,6,1,"","severity_default"],[14,6,1,"","severity_map"],[14,6,1,"","timestamp_override"]],"sigma.serializer.elastic.ElasticSecurityRule.Schema.Config":[[14,6,1,"","extra"],[14,6,1,"","schema_extra"]],"sigma.serializer.elastic.ElasticSecuritySlackAction":[[14,1,1,"","Config"],[14,6,1,"","message"],[14,2,1,"","to_rule_format"],[14,6,1,"","type"]],"sigma.serializer.elastic.ElasticSecuritySlackAction.Config":[[14,6,1,"","schema_extra"]],"sigma.serializer.elastic.ElasticSecurityWebhookAction":[[14,1,1,"","Config"],[14,6,1,"","body"],[14,2,1,"","to_rule_format"],[14,6,1,"","type"]],"sigma.serializer.elastic.ElasticSecurityWebhookAction.Config":[[14,6,1,"","schema_extra"]],"sigma.serializer.elastic.EventQueryLanguage":[[14,1,1,"","Schema"],[14,2,1,"","serialize"],[14,6,1,"","transforms"]],"sigma.serializer.elastic.EventQueryLanguage.Schema":[[14,1,1,"","Config"],[14,6,1,"","and_format"],[14,6,1,"","escape"],[14,6,1,"","escaped_characters"],[14,6,1,"","field_contains"],[14,6,1,"","field_endswith"],[14,6,1,"","field_equality"],[14,6,1,"","field_like"],[14,6,1,"","field_lookup"],[14,6,1,"","field_lookup_regex"],[14,6,1,"","field_match"],[14,6,1,"","field_not_empty"],[14,6,1,"","field_regex"],[14,6,1,"","field_startswith"],[14,6,1,"","grouping"],[14,6,1,"","keyword"],[14,6,1,"","list_separator"],[14,6,1,"","not_format"],[14,6,1,"","or_format"],[14,6,1,"","prepend_result"],[14,6,1,"","quote"],[14,6,1,"","rule_separator"]],"sigma.serializer.elastic.EventQueryLanguage.Schema.Config":[[14,6,1,"","schema_extra"]],"sigma.serializer.elastic.KibanaQueryLanguage":[[14,1,1,"","Schema"],[14,6,1,"","transforms"]],"sigma.serializer.elastic.KibanaQueryLanguage.Schema":[[14,1,1,"","Config"],[14,6,1,"","and_format"],[14,6,1,"","escape"],[14,6,1,"","escaped_characters"],[14,6,1,"","field_contains"],[14,6,1,"","field_endswith"],[14,6,1,"","field_equality"],[14,6,1,"","field_like"],[14,6,1,"","field_lookup"],[14,6,1,"","field_lookup_regex"],[14,6,1,"","field_match"],[14,6,1,"","field_not_empty"],[14,6,1,"","field_regex"],[14,6,1,"","field_startswith"],[14,6,1,"","grouping"],[14,6,1,"","keyword"],[14,6,1,"","list_separator"],[14,6,1,"","not_format"],[14,6,1,"","or_format"],[14,6,1,"","quote"],[14,6,1,"","rule_separator"]],"sigma.serializer.elastic.KibanaQueryLanguage.Schema.Config":[[14,6,1,"","schema_extra"]],"sigma.transform":[[15,1,1,"","AddTags"],[15,1,1,"","ContainsToMatch"],[15,1,1,"","ExpressionType"],[15,1,1,"","FieldFuzzyMap"],[15,1,1,"","FieldMap"],[15,1,1,"","FieldMatchReplace"],[15,1,1,"","Transformation"]],"sigma.transform.AddTags":[[15,1,1,"","Schema"],[15,2,1,"","transform_rule"]],"sigma.transform.AddTags.Schema":[[15,1,1,"","Config"],[15,6,1,"","tags"],[15,6,1,"","type"]],"sigma.transform.AddTags.Schema.Config":[[15,6,1,"","extra"],[15,6,1,"","schema_extra"]],"sigma.transform.ContainsToMatch":[[15,2,1,"","transform_expression"]],"sigma.transform.ExpressionType":[[15,6,1,"","CONTAINS"],[15,6,1,"","ENDSWITH"],[15,6,1,"","STARTSWITH"]],"sigma.transform.FieldFuzzyMap":[[15,1,1,"","Schema"],[15,2,1,"","transform_expression"]],"sigma.transform.FieldFuzzyMap.Schema":[[15,1,1,"","Config"],[15,6,1,"","mapping"],[15,6,1,"","skip_unknown"],[15,6,1,"","type"]],"sigma.transform.FieldFuzzyMap.Schema.Config":[[15,6,1,"","extra"],[15,6,1,"","schema_extra"]],"sigma.transform.FieldMap":[[15,1,1,"","Schema"],[15,2,1,"","transform_expression"]],"sigma.transform.FieldMap.Schema":[[15,1,1,"","Config"],[15,6,1,"","mapping"],[15,6,1,"","skip_unknown"],[15,6,1,"","type"]],"sigma.transform.FieldMap.Schema.Config":[[15,6,1,"","extra"],[15,6,1,"","schema_extra"]],"sigma.transform.FieldMatchReplace":[[15,1,1,"","Schema"],[15,6,1,"","VALID_TYPES"],[15,2,1,"","transform_expression"]],"sigma.transform.FieldMatchReplace.Schema":[[15,1,1,"","Config"],[15,6,1,"","expression"],[15,6,1,"","field"],[15,6,1,"","pattern"],[15,6,1,"","target"],[15,6,1,"","type"]],"sigma.transform.FieldMatchReplace.Schema.Config":[[15,6,1,"","extra"],[15,6,1,"","schema_extra"]],"sigma.transform.Transformation":[[15,1,1,"","Schema"],[15,2,1,"","enumerate_builtin"],[15,2,1,"","lookup_class"],[15,2,1,"","transform_expression"],[15,2,1,"","transform_rule"],[15,2,1,"","transform_serializer"]],"sigma.transform.Transformation.Schema":[[15,1,1,"","Config"],[15,2,1,"","load"],[15,6,1,"","type"]],"sigma.transform.Transformation.Schema.Config":[[15,6,1,"","extra"]],"sigma.util":[[16,1,1,"","CopyableSchema"],[16,3,1,"","iter_chunked"]],"sigma.util.CopyableSchema":[[16,2,1,"","copy_schema"],[16,6,1,"","schema_extra"]],sigma:[[2,0,0,"-","cli"],[9,0,0,"-","errors"],[10,0,0,"-","grammar"],[11,0,0,"-","mitre"],[12,0,0,"-","schema"],[13,0,0,"-","serializer"],[15,0,0,"-","transform"],[16,0,0,"-","util"]]},objnames:{"0":["py","module","Python module"],"1":["py","class","Python class"],"2":["py","method","Python method"],"3":["py","function","Python function"],"4":["py","exception","Python exception"],"5":["py","property","Python property"],"6":["py","attribute","Python attribute"]},objtypes:{"0":"py:module","1":"py:class","2":"py:method","3":"py:function","4":"py:exception","5":"py:property","6":"py:attribute"},terms:{"0":[2,12,14],"001":12,"03":20,"07":12,"1":[2,17],"10":14,"100":[12,14,20],"12":12,"1234":12,"14":20,"15":12,"159489a390df":12,"2":17,"2019":12,"2020":20,"2021":12,"20t14":20,"23":20,"25":14,"256":12,"28":20,"28b9":12,"3":[17,20],"30":12,"31":12,"35":[14,20],"382748":20,"3d":12,"4":17,"4344":12,"5":[14,17,20],"535":12,"5m":[12,14,20],"65":[12,14,20],"75":14,"7aa7009a":12,"8":2,"8c1f":12,"95":[14,20],"abstract":[10,11,13,19],"boolean":13,"byte":10,"case":[12,13,14,15],"catch":2,"class":[1,2,10,11,12,13,14,15,16,17,18,19,20],"default":[13,14,15,19,20],"do":18,"enum":[12,14,15],"final":21,"function":[1,12],"import":[1,12,17,18],"int":[9,10,12,14,16,17],"long":12,"new":[10,12,13,14,15,18,21],"null":[10,14],"return":[1,2,10,12,13,14,15,17,18,21],"short":12,"static":13,"super":15,"switch":12,"true":[10,13,14,17,20],"while":[10,12,20],A:[1,2,9,10,12,13,14,15,18,20,21],AND:[10,12,13,14,18,21],And:10,As:[15,18,20],At:20,By:20,For:[1,18,19,20],If:[12,13,14,15,20,21],In:13,It:[12,17,20],NO:14,NOT:[13,14],No:12,OR:[10,12,13,14,18],One:13,Or:10,The:[1,9,10,12,13,14,15,17,18,19,20,21],Their:20,There:[9,10,20],These:[10,12],To:[2,18],With:19,__init__:15,a53a02b997935fd8eedcb5f7abab9b9f:12,abc:[11,13,15],abil:19,abov:[14,18,20,21],accept:15,access:[17,18],accord:[2,12,21],across:[13,14],action:[12,14,21],activ:[12,17,19],ad:[2,18,20],add:[2,13,15],add_command:2,add_tag:15,addtag:15,adjust:20,after:[9,12,17],against:[13,15,21],alert:[12,14,20],alia:12,aliased_group:2,all:[9,10,12,13,14,15,18,20,21],allow:[12,15,17,18,20],almost:12,along:[1,19],alongsid:18,also:[1,12,13,15,21],alwai:[9,13],amount:12,ampliasecur:12,an:[9,10,12,13,14,15,17,18,19,20,21],analysi:12,analyst:12,and_format:[13,14],ani:[2,10,12,13,14,15,16,17,18,20,21],anoth:[12,13,14,19,21],anymor:12,api:[19,20],append:[13,18],appli:[2,12,13,14,17,20,21],applic:[12,14],apply_rule_transform:13,ar:[1,9,10,12,13,14,17,18,20,21],arbitrari:[12,13,17,21],aren:[12,15],arg:[2,10,12,18,19],argument:[2,9,13,17,19],articl:12,asid:[13,14],assist:1,associ:[12,13],att:19,attach:[2,14],attack:[11,12,15,18],attack_singleton:11,attack_url:11,attr:2,attribut:[2,12],author:[1,12],automat:2,avail:20,back:[1,12,13,15],backend:[15,19,21],bare:20,base64:10,base64_modifi:10,base64fieldequ:10,base64offset:10,base64offset_modifi:10,base:[2,9,10,11,12,13,14,15,16,17,18,19],base_class:13,basecorrel:12,basemodel:[10,11,12,13,14,15],basi:12,basic:[13,17],bcc:[14,20],becaus:12,been:20,being:[15,18],below:[18,20,21],between:[15,19],beyond:20,blog:12,bodi:[14,20],bool:[10,13,14,15,17],bool_fals:[13,14],bool_tru:[13,14],both:[18,20,21],bound:12,brief:12,brows:19,build:[10,12,13],build_express:12,build_grammar_pars:10,build_key_value_express:10,built:[1,13,15,19,20],builtin:13,cach:19,calebstewart:19,call:[2,15,18],callabl:10,callback:[2,10],camelcas:15,can:[1,2,12,13,15,17,18,19,20,21],categori:[12,13,14,21],categoris:12,caus:13,cc:[14,20],cd:19,chain:17,chang:[2,18,19],charact:[12,13,14],check:10,ck:19,classmethod:[10,11,12,13,15,16],classnam:[13,15,19,21],classvar:[10,11,12,13,14],clazz:[14,20],cli:[0,1,19],click:2,clone:19,clussvc:12,cmd:21,cmd_name:2,code:21,collaps:10,collect:12,collis:12,column:9,com:[11,12,14,19,20],combin:[9,12,13,14,19,20],come:[1,20],command:[2,3,12,17,18,21],command_class:2,command_lin:15,commandlin:[12,15,21],commandwithverbos:2,common:[12,13,15,19,21],commonli:15,commonserializerschema:[13,14,17],compani:[14,20],compar:[10,13,15,21],comparison:[9,10,15],compat:21,complet:[13,18],completed_modifi:9,compliant:[12,14],compon:[14,20],condit:[1,9,10,12,13,15,17,18,19,20,21],conditionsyntaxerror:9,config:[9,12,13,14,15,17,18],configur:[1,2,13,14,15,19,20],conflict:20,conform:[13,20],conjunct:12,connector:[14,20],consid:12,constrainedstrvalu:12,construct:[1,10,12,13,14,15,19,21],contain:[1,9,12,13,14,15,17,21],containstomatch:15,context:[2,14,15],contextmanag:15,control:[13,20],convers:[9,12,19],convert:[1,2,10,12,13,14,15,17,19,20,21],copy_schema:[16,17,18],copyableschema:[13,14,16,17,18],core:[1,2,10,12],coreexpress:10,correct:[13,14],correl:[9,12],correlationgreaterthan:12,correlationgreaterthanequ:12,correlationlessthan:12,correlationlessthanequ:12,correlationrang:12,correlationsimplecondit:12,correlationtyp:12,correspond:20,could:[12,13,15,19,20,21],countcorrel:12,cover:12,creat:[2,12,19,20,21],creator:12,credenti:12,credential_access:12,criteria:[12,13],critic:[12,14,20],cti:11,ctx:2,current:[9,12,13,14],custom:[2,12,13,15,17,18,19,20,21],custom_tag1:15,custom_tag2:15,custom_tag:18,customseri:[17,21],customtransform:[15,18],dashboard:12,data:[11,12,14,17,18,19,21],date:[11,12,14],datetim:[12,14],dd:12,declar:[2,12],decor:2,dedup_kei:[14,20],def:[15,17,18],default_format:[13,14],defaultindex:[13,14,21],defer:19,defin:[1,10,12,13,14,15,17,18,20,21],definit:[10,12,13,15,17,19],depend:[13,21],deprec:12,deriv:12,describ:[12,20],descript:[12,13,14,15,21],detail:[1,11,13,20],detect:[1,9,10,12,13,14,15,17,19,21],develop:[12,19],dict:[2,10,12,13,14,15,16,21],dictionari:[1,12,13,14,20],differ:[13,18,20,21],direct:10,directli:[2,10,12,13,19,20,21],disabl:20,disk:[1,12],displai:12,doc:[19,20],document:[9,12,20],doe:[12,18,20,21],don:[10,18],done:15,dot:12,download:[11,19],due:20,dump:[1,9,13,14,19],duplic:[9,17,18],duplicaterulenameerror:9,dure:[1,9,15,20],e96a73c7bf33a464c510ede582318bf2:12,e:[12,13,14,18,19,20],each:[10,13,15,18,20,21],easi:1,easier:17,easili:[17,18],editor:12,either:[10,12,13,14,15,18],elast:[1,13,21],elasticsearch:14,elasticsecurityact:20,elasticsecurityactiontyp:14,elasticsecuritybaseact:14,elasticsecurityemailact:14,elasticsecuritypagerdutyact:14,elasticsecurityrul:14,elasticsecurityslackact:14,elasticsecuritywebhookact:14,elif:18,els:18,email:[14,20],empti:[12,13],enabl:[14,17,20],enable_rul:[14,20],encod:10,end:[10,13,14],endswith:[12,14,15],engin:[13,14],enrich:12,enter:19,enterpris:11,entir:[15,18],entri:12,enumer:[12,14,15],enumerate_builtin:15,environ:19,eql:[1,13,14,19,21],equal:[10,13,14,15],equival:13,error:[0,1,13],error_wrapp:9,es:[14,19,20],escap:[13,14],escaped_charact:[13,14],especi:21,etc:12,evalu:[10,12,15],even:12,event:[12,14,21],event_act:[14,20],event_count:12,eventquerylanguag:14,everi:[13,20],everyth:12,ex:[12,15,21],exact:18,exampl:[12,13,14,15,16,18,19,20,21],example_extra:[16,17,18],except:[2,9,10,12,13,15],execut:[10,15,20],exist:[2,12,13,14],exit:[15,19],expect:[9,12],experiment:12,explicit:[15,21],explicitli:15,express:[10,12,13,14,15,17,19],expressiontyp:15,extend:[15,17,18],extra:[12,14,15,17,18,19,20,21],extra_data:[12,15],extra_tag:18,extrem:17,ey:10,f:[1,18],facilit:[10,13],fail:9,failed_modifi:9,fals:[10,12,13,14,15],falseposit:12,feel:12,few:[20,21],field:[1,9,10,12,13,14,15,17,18,20,21],field_contain:[13,14],field_endswith:[13,14],field_equ:[13,14],field_fuzzy_map:15,field_lik:[13,14],field_lookup:[13,14],field_lookup_regex:[13,14],field_map:[15,19,21],field_match:[13,14],field_not_empti:[13,14],field_regex:[13,14],field_startswith:[13,14],fieldcomparison:[10,15],fieldcontain:[10,15],fieldendswith:[10,15],fieldequ:10,fieldfuzzymap:15,fieldlik:10,fieldlookup:10,fieldlookupregex:10,fieldmap:15,fieldmatchreplac:15,fieldnotempti:10,fieldregex:10,fieldstartswith:[10,15],fieldtransform:15,file:[1,9,12,13,14,19,20,21],filenam:[12,19],filepath:12,filter:[12,14],fine:12,fire:[14,20],first:[12,13,20,21],five:12,florian:12,fmt:9,follow:[12,13,14,15,17,20,21],forbid:[14,15],form:20,format:[9,12,13,14,15,18,19,20,21],former:20,forward:[12,20],found:9,framework:[1,11],free:[12,20],frequent:12,from:[1,10,12,13,14,15,17,18,19,20,21],from_dict:13,from_pars:10,from_sigma:12,from_yaml:[1,12,13],full:[12,21],fulli:[10,13,15,21],further:[12,13,20],futur:[17,18,19],fuzzi:2,fuzzyaliasedgroup:2,fuzzywuzzi:2,g:[12,13,14,20],gener:[9,12,13,15,16,20],get_builtin_seri:13,get_command:2,get_express:12,get_serializer_class:13,get_tact:11,get_techniqu:11,git:19,github:[12,19],githubusercont:11,given:[2,9,10,12,13,14,15,18,19,21],glob:[12,13,14],global:12,go:10,grab:10,grammar:[0,1,12,15,18,19],grammar_pars:12,group:[2,10,12,13,14,15,20],group_bi:12,gt:12,gte:12,ha:[12,15],had:12,handl:[1,10,12],have:[12,13,20],hello:17,help:[13,19],helper:9,here:[10,15,20],high:[12,14,18,20],highli:12,highlight:[13,14],home:12,how:[13,14,18,21],howev:21,http:[11,12,19],huge:12,hyphen:12,i:[10,18],id:[11,12,14,20],identifi:[9,10,12,13],ignor:[13,15],ignore_skip:[13,14],imag:[12,15,21],immedi:[2,12],imphash:12,implement:[1,10,15,17,18,19],importlib:[11,13],incid:12,includ:12,includeschema:12,incorrect:9,index:[13,14,19,20,21],indic:[12,13,14,21],individu:[15,18],inform:[12,14,15,20],ingest:[1,14,19,20],inherit:[13,17,18,21],initi:13,inlin:[1,15],input:13,inspect:[12,13],instanc:[10,13,15,17,18],instanti:[12,18,21],instead:[10,12,20],integ:[12,20],intend:12,interact:[10,19],interest:12,interfac:[3,12],intern:[12,13,18],interv:[14,20],invalid:9,invalidfieldvalueerror:9,invalidmodifiercombinationerror:9,invoc:2,invok:2,isinst:[17,18],issu:12,item:[13,14,20],iter:[12,13],iter_chunk:16,its:12,itself:13,join:[13,21],json:[1,11,12,13,14,19,20,21],keep:12,kei:[10,18],keyword:[2,10,12,13,14],keywordsearch:10,kibana:14,kibanaquerylanguag:14,known:12,kql:[1,14,19],kwarg:[2,12],languag:[1,14,21],last:12,lastli:1,latter:[13,20],lead:12,least:[20,21],leav:10,length:13,letter:12,level:[12,14,18,20],licens:12,like:[9,10,13,14,18],line:[3,9,12],lineno:9,link:12,list:[1,2,9,10,11,12,13,14,15,17,18,19,20,21],list_of_indic:13,list_separ:[13,14],liter:[10,12,13,14,15],load:[1,11,12,13,15,17,19],loc:10,local:13,locat:11,log:[2,9,12,13,14,19],logic:[10,12,13,14,20,21],logicaland:[10,18],logicalexpress:10,logicalnot:10,logicalor:[10,18],logsourc:[12,13,14,20,21],logsourcematch:13,logsourcerul:[13,14],look:18,lookup:[10,11,12,15],lookup_class:15,lookup_express:12,low:[12,14,20],lower:12,lowercasestr:12,lt:12,lte:12,made:[12,13],mai:[12,13,17,18,19,21],main:[10,11,12,13,14,15],mainli:[9,13],major:1,make:[1,18],malici:12,manag:[15,19],manual:12,map:[1,14,15,20,21],master:11,match:[2,10,12,13,14,15,18,20,21],match_replac:15,match_rul:13,max:12,max_sign:[14,20],maximum:[12,20],mean:[18,21],meant:12,medium:[12,14,20],memori:[1,12,13,21],merg:[12,13,14,21],merge_config:[13,14],messag:[9,14,19,20],method:[1,9,12,13,15,17,18],mind:19,minimum:[12,13],miss:21,missingcorrelationrul:9,missingidentifi:12,mitr:[0,1,2,19],mm:12,mobil:11,model:[17,18],modif:[1,15,18],modifi:[1,9,10,12,13,15,18,19,20],modified_rul:13,modul:[0,1,2,13,15,18,19,21],more:[1,9,12,13],morph:20,most:[9,15],mostli:[17,20],multipl:[9,13,14,21],multiplecorrelationerror:9,must:[10,13,14,15,17,18,20,21],my:[18,20,21],my_command_line_field:21,my_config:17,my_custom:14,my_custom_tag:14,my_imag:21,n:14,name:[2,9,12,13,14,15,21],namespac:12,nativ:[1,12],necessari:[12,13,21],need:[10,12,15],neg:13,nest:12,never:12,newlin:13,nocorrelationdocu:9,noisi:12,non:18,none:[2,9,10,11,12,13,14,15,16],normal:[12,15,18],not_format:[13,14],notabl:12,note:10,notif:14,number:[12,13,20],numer:12,o:19,obj:12,object:[1,2,12,13,15,16,18,20,21],obsolet:12,occur:12,off:13,offici:20,oh:14,omit:18,one:[9,12,13,15,20],ones:10,onli:[13,17,20],oper:[10,15],oppos:10,option:[2,9,10,11,12,13,14,15,17,18,19,20,21],or_format:[13,14],order:21,organ:13,orient:12,origin:[13,15],os:12,other:[9,12,13,20,21],other_config:17,our:[13,14],output:[13,14,20,21],output_index:[14,20],outsid:12,over:13,overrid:19,own:[17,18,19,20],packag:[0,12,18,19,21],page:19,pagerduti:[14,20],pair:[10,18],paper:12,paramet:[2,9,13,14,15],parent:[2,10,15],parenthes:2,parentimag:[12,15],pars:[1,10,12],parse_grammar:12,parse_obj:12,parseexcept:9,parser:[10,12],parseresult:10,parsing_error:9,parti:19,pass:[2,13,21],path:[11,12,13,15,21],pathlib:[11,12,13],pathlik:12,pattern:[10,12,13,14,15],per:20,perform:[20,21],period:12,pip:19,platform:[1,12],poetri:19,posit:[12,13],possibl:[12,13,18,20],post_init:12,postprocess:10,pre:11,predefin:12,prepend:14,prepend_result:14,present:12,pretti:[13,14],previous:12,print:[1,12],prior:[2,12,17,20,21],privat:12,process:[9,10,13,15],process_cr:[1,12,13,14,21],produc:[12,13,20],product:[12,13,14,21],project:19,prompt:12,properti:[9,10,11,12,13,17,18,20],propos:12,provid:[2,9,12,13,14,15,17,18,19,20,21],pseudo:21,pull:12,pydant:[1,9,10,11,12,13,14,15,17,18],pypars:[1,9,10,12],pysigma:10,python:[1,10,12,13,15,20,21],qualifi:[13,15,21],queri:[1,12,13,14,21],quot:[13,14],r:17,rais:[9,12,13,15],rang:12,rare:12,rate:12,raw:[11,13,20],re:1,reaction:12,read:12,reason:12,recommend:[12,17],recurs:[15,18],refer:[10,12,13,18],regardless:13,regex:[10,13,14,15],regist:2,regular:[10,12,15],rel:[18,20],relat:[12,20],relationship:12,relev:12,remain:12,remov:15,renam:[12,20],replac:[10,12,15],repositori:19,repr:17,repres:[10,12,13,14,17],represent:[12,13],reproduc:12,request:[9,12,13],requir:[12,13,14,18,20,21],research:12,resolv:[10,12],respect:[13,20],rest:20,restrict:13,result:[10,12,14],retriev:[12,13],reus:15,review:12,right:2,rip:10,risk:[14,20],risk_default:[14,20],risk_map:[14,20],root:21,roth:12,rule:[1,9,10,12,13,14,15,19,21],rule_separ:14,ruledetect:[10,12],ruledetectionfield:[12,13],ruledetectionlist:12,rulelevel:12,rulelicens:12,rulelogsourc:12,rulerel:12,rulerelationtyp:12,rulestatu:12,ruletag:[12,14,15,18],rulevalidationerror:9,runtim:[17,18],s0005:12,s:[1,10,12,13,14,20,21],safe:12,same:[2,9,10,12,13,18,20],sampl:21,save:[1,11,12],schema:[0,1,2,9,10,13,14,17,18,19,20,21],schema_extra:[12,13,14,15,16,17,18],scheme:12,search:[10,12,13,19],section:[12,13],secur:[12,14,21],see:[1,13,18,20],seen:13,select:13,selection1:12,selection2:12,selector:[10,13],self:[15,17,18],send:[12,14],sentenc:12,separ:[12,13,14],seq:16,sequenc:[2,16],serial:[0,1,9,10,12,15,18,19],serializ:[1,12],serializerclass:17,serializernotfound:9,serializervalidationerror:9,servic:[12,13,21],set:[2,12,14,20],setup:[18,19],sever:[12,14,20],severity_default:[14,20],severity_map:[14,20],shell:19,shortcut:[2,10],should:[10,12,13,15,17,19,20],shouldn:12,show:[18,19],shrug:20,siem:[14,20],sigma:[17,18,20,21],sigmaerror:9,sigmahq:12,sigmavalidationerror:9,signal:[14,20],similar:13,simpl:[12,17],simpled:12,simpli:[13,15],singl:[12,13,14,18,20],singular:12,situat:10,size:16,skip:9,skip_unknown:15,skiprul:[9,13,15],slack:[14,20],slightli:20,snake_cas:15,so:[15,18,19],solut:20,some:[12,13,15,17],someon:20,someoneels:20,someth:20,somewher:10,sourc:[12,13,14,15,19,20],source_typ:11,space:12,spdx:12,spec:15,special:[12,18],specif:[9,10,12,15,18,19,20,21],specifi:[9,11,12,13,15,20,21],splunk:13,stabl:12,standard:19,start:[10,13,14],startswith:[14,15],state:12,statement:18,statu:12,stdout:19,still:12,str:[2,9,10,11,12,13,14,15,16,17,18],straight:20,straightforward:18,string:[10,12,13,14,15,20,21],stringcontain:14,structur:[10,15,21],sub:[2,15],subclass:9,subject:[14,20],submodul:[0,19],subpackag:[0,19],substitut:15,suitabl:20,summari:[14,20],support:13,suppos:12,swap:18,syntax:[9,12,13,14,20],system:[12,19,21],t1003:12,t12345:[15,18],t1234:12,t:[10,12,15,16,18],tactic:11,tactit:11,tag:[12,14,15,18,20],take:[2,17,18,21],taken:10,target:[13,15,21],technic:12,techniqu:[11,12],tempor:12,temporalcorrel:12,temporari:15,term:12,test:[10,12,13,14,15],text:[13,14],textqueryseri:[13,14],them:[1,2,12],themselv:20,thi:[1,2,9,10,12,13,14,15,17,18,19,20,21],thing:[10,13],third:19,three:21,through:[1,17],time:[14,20],timefram:12,timespan:12,timestamp:[14,20],timestamp_overrid:[14,20],titl:[1,11,12,15,18],title_format:18,to_detect:10,to_field_with_modifi:10,to_rule_format:14,to_sever:12,to_sigma:[1,12],token:10,top:20,touch:21,traceback:2,transform:[0,1,2,9,10,12,13,14,19,20],transform_express:[15,18],transform_rul:[15,18],transform_seri:15,transformvalidationerror:9,transorm:12,travers:[11,13],tree:10,trigger:[12,14,20],tune:12,tupl:[10,13,15],tweet:12,two:[10,15,18,20],type:[9,10,12,13,14,15,17,18,20,21],type_:9,unalt:15,unchang:10,under:19,underscor:12,understand:10,unhandl:2,union:[2,10,11,12,13,14,17],uniqu:12,unknownidentifiererror:9,unknownmodifiererror:9,unknownrulenameerror:9,unknowntransform:9,unspecifi:14,unsupport:[9,12],unsupportedfieldcomparison:9,unsupportedserializerformat:[9,13],up:[2,11],updat:[19,21],update_express:12,upload:20,url:11,us:[1,2,9,12,13,14,15,17,18,19,20,21],usag:[19,20],useless:17,user:[17,18],utf16_modifi:10,utf16be_modifi:10,utf16l:10,utf16le_modifi:10,util:[0,1,13,14,17,18,20,21],uuid:12,v:[12,13],valid:[1,2,9,10,12,13,15,19,20,21],valid_typ:15,validate_detect:[12,13],validationerror:9,valu:[9,10,12,13,14,15,18,20],value_count:12,varieti:[1,13],variou:19,verbos:2,version:[2,15,18,20],via:[17,18,21],view:[17,18,21],virtual:19,visit:10,wa:[9,12,20],wai:[2,9,12],wce:12,we:15,webhook:[14,20],well:[17,18,19],what:[10,12],when:[9,10,13,14,15,18,19,20,21],where:20,whether:[13,14],which:[1,10,12,13,14,15,17,18,19,20,21],who:[17,18],whole:[12,15,18],wide_modifi:10,wiki:12,wildcard:[10,15],win_susp_net_execut:1,window:[1,12,13,14,21],windows_process_cr:21,within:[13,15,18,20,21],without:[2,12,21],world:17,would:20,write:[12,21],written:12,www:12,yaml:[1,9,12,13,14,15,18,19,21],yield:[13,15],yml:[1,12,19,20],you:[1,10,12,13,15,17,18,19,20,21],your:[13,14,15,17,18,19,20,21],yyyi:12},titles:["sigma","sigma package","sigma.cli package","sigma.cli.converter module","sigma.cli.list module","sigma.cli.mitre module","sigma.cli.schema module","sigma.cli.transform module","sigma.cli.validate module","sigma.errors module","sigma.grammar module","sigma.mitre module","sigma.schema module","sigma.serializer package","sigma.serializer.elastic module","sigma.transform package","sigma.util module","Creating Rule Serializers","Creating Rule Transformations","Welcome to Python Sigma\u2019s documentation!","Elastic Serializers","Serializer Configurations"],titleterms:{"class":21,action:20,base:21,built:21,cli:[2,3,4,5,6,7,8],command:19,configur:[17,18,21],content:19,convert:3,creat:[17,18],definit:21,document:19,elast:[14,20],eql:20,error:9,event:20,exampl:17,express:18,grammar:10,indic:19,instal:19,interfac:19,languag:20,line:19,list:4,log:21,mitr:[5,11],modul:[3,4,5,6,7,8,9,10,11,12,14,16],packag:[1,2,13,15],python:19,queri:20,rule:[17,18,20],s:19,schema:[6,12,15],secur:20,serial:[13,14,17,20,21],sigma:[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,19],sourc:21,submodul:[1,2,13],subpackag:1,tabl:19,transform:[7,15,17,18,21],util:16,valid:8,welcom:19}})