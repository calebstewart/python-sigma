Search.setIndex({docnames:["api/modules","api/sigma","api/sigma.cli","api/sigma.cli.converter","api/sigma.cli.elastic","api/sigma.cli.list","api/sigma.cli.mitre","api/sigma.cli.schema","api/sigma.cli.transform","api/sigma.cli.validate","api/sigma.errors","api/sigma.grammar","api/sigma.mitre","api/sigma.schema","api/sigma.serializer","api/sigma.serializer.elastic","api/sigma.transform","api/sigma.util","custom-serializers","custom-transformations","index","serializers/elastic","serializers/index"],envversion:{"sphinx.domains.c":2,"sphinx.domains.changeset":1,"sphinx.domains.citation":1,"sphinx.domains.cpp":4,"sphinx.domains.index":1,"sphinx.domains.javascript":2,"sphinx.domains.math":2,"sphinx.domains.python":3,"sphinx.domains.rst":2,"sphinx.domains.std":2,sphinx:56},filenames:["api/modules.rst","api/sigma.rst","api/sigma.cli.rst","api/sigma.cli.converter.rst","api/sigma.cli.elastic.rst","api/sigma.cli.list.rst","api/sigma.cli.mitre.rst","api/sigma.cli.schema.rst","api/sigma.cli.transform.rst","api/sigma.cli.validate.rst","api/sigma.errors.rst","api/sigma.grammar.rst","api/sigma.mitre.rst","api/sigma.schema.rst","api/sigma.serializer.rst","api/sigma.serializer.elastic.rst","api/sigma.transform.rst","api/sigma.util.rst","custom-serializers.rst","custom-transformations.rst","index.rst","serializers/elastic.rst","serializers/index.rst"],objects:{"":[[1,0,0,"-","sigma"]],"sigma.cli":[[2,1,1,"","CommandWithVerbosity"],[2,1,1,"","FuzzyAliasedGroup"],[2,3,1,"","aliased_group"],[3,0,0,"-","converter"],[4,0,0,"-","elastic"],[5,0,0,"-","list"],[6,0,0,"-","mitre"],[7,0,0,"-","schema"],[8,0,0,"-","transform"],[9,0,0,"-","validate"]],"sigma.cli.CommandWithVerbosity":[[2,2,1,"","invoke"]],"sigma.cli.FuzzyAliasedGroup":[[2,2,1,"","command"],[2,2,1,"","get_command"]],"sigma.cli.elastic":[[4,1,1,"","ElasticDeploymentSpec"],[4,3,1,"","load_rules_from_paths"]],"sigma.cli.elastic.ElasticDeploymentSpec":[[4,4,1,"","rules"],[4,4,1,"","serializers"]],"sigma.errors":[[10,5,1,"","ConditionSyntaxError"],[10,5,1,"","DuplicateRuleNameError"],[10,5,1,"","InvalidFieldValueError"],[10,5,1,"","InvalidModifierCombinationError"],[10,5,1,"","MissingCorrelationRule"],[10,5,1,"","MultipleCorrelationError"],[10,5,1,"","NoCorrelationDocument"],[10,5,1,"","RuleValidationError"],[10,5,1,"","SerializerNotFound"],[10,5,1,"","SerializerValidationError"],[10,5,1,"","SigmaError"],[10,5,1,"","SigmaValidationError"],[10,5,1,"","SkipRule"],[10,5,1,"","TransformValidationError"],[10,5,1,"","UnknownIdentifierError"],[10,5,1,"","UnknownModifierError"],[10,5,1,"","UnknownRuleNameError"],[10,5,1,"","UnknownTransform"],[10,5,1,"","UnsupportedSerializerFormat"]],"sigma.errors.ConditionSyntaxError":[[10,6,1,"","column"],[10,6,1,"","line"],[10,6,1,"","lineno"],[10,6,1,"","message"]],"sigma.errors.SkipRule":[[10,2,1,"","log"]],"sigma.grammar":[[11,1,1,"","Base64FieldEquality"],[11,1,1,"","CoreExpression"],[11,1,1,"","Expression"],[11,1,1,"","FieldComparison"],[11,1,1,"","FieldContains"],[11,1,1,"","FieldEndsWith"],[11,1,1,"","FieldEquality"],[11,1,1,"","FieldLike"],[11,1,1,"","FieldLookup"],[11,1,1,"","FieldLookupRegex"],[11,1,1,"","FieldNotEmpty"],[11,1,1,"","FieldRegex"],[11,1,1,"","FieldStartsWith"],[11,1,1,"","Identifier"],[11,1,1,"","KeywordSearch"],[11,1,1,"","LogicalAnd"],[11,1,1,"","LogicalExpression"],[11,1,1,"","LogicalNot"],[11,1,1,"","LogicalOr"],[11,1,1,"","Selector"],[11,3,1,"","base64_modifier"],[11,3,1,"","base64offset_modifier"],[11,3,1,"","build_grammar_parser"],[11,3,1,"","build_key_value_expression"],[11,3,1,"","utf16_modifier"],[11,3,1,"","utf16be_modifier"],[11,3,1,"","utf16le_modifier"],[11,3,1,"","wide_modifier"]],"sigma.grammar.Base64FieldEquality":[[11,2,1,"","to_detection"],[11,4,1,"","value"]],"sigma.grammar.CoreExpression":[[11,4,1,"","args"],[11,2,1,"","from_parsed"],[11,2,1,"","postprocess"]],"sigma.grammar.Expression":[[11,4,1,"","operator"],[11,4,1,"","parent"],[11,2,1,"","postprocess"],[11,2,1,"","to_detection"],[11,2,1,"","visit"]],"sigma.grammar.FieldComparison":[[11,4,1,"","field"],[11,2,1,"","to_detection"],[11,2,1,"","to_field_with_modifiers"],[11,4,1,"","value"]],"sigma.grammar.FieldContains":[[11,2,1,"","to_detection"],[11,2,1,"","to_field_with_modifiers"],[11,4,1,"","value"]],"sigma.grammar.FieldEndsWith":[[11,2,1,"","to_detection"],[11,2,1,"","to_field_with_modifiers"],[11,4,1,"","value"]],"sigma.grammar.FieldEquality":[[11,4,1,"","field"],[11,4,1,"","parent"],[11,2,1,"","to_detection"],[11,4,1,"","value"]],"sigma.grammar.FieldLike":[[11,4,1,"","field"],[11,4,1,"","parent"],[11,2,1,"","to_detection"],[11,4,1,"","value"]],"sigma.grammar.FieldLookup":[[11,4,1,"","value"]],"sigma.grammar.FieldLookupRegex":[[11,2,1,"","to_field_with_modifiers"],[11,4,1,"","value"]],"sigma.grammar.FieldNotEmpty":[[11,2,1,"","to_detection"],[11,4,1,"","value"]],"sigma.grammar.FieldRegex":[[11,2,1,"","to_detection"],[11,2,1,"","to_field_with_modifiers"],[11,4,1,"","value"]],"sigma.grammar.FieldStartsWith":[[11,2,1,"","to_detection"],[11,2,1,"","to_field_with_modifiers"],[11,4,1,"","value"]],"sigma.grammar.Identifier":[[11,4,1,"","args"],[11,6,1,"","identifier"],[11,4,1,"","parent"],[11,2,1,"","postprocess"]],"sigma.grammar.KeywordSearch":[[11,2,1,"","to_detection"],[11,4,1,"","value"]],"sigma.grammar.LogicalAnd":[[11,4,1,"","operator"],[11,2,1,"","postprocess"],[11,2,1,"","to_detection"]],"sigma.grammar.LogicalExpression":[[11,4,1,"","operator"],[11,2,1,"","postprocess"]],"sigma.grammar.LogicalNot":[[11,4,1,"","operator"],[11,2,1,"","postprocess"],[11,2,1,"","to_detection"]],"sigma.grammar.LogicalOr":[[11,4,1,"","operator"],[11,2,1,"","postprocess"],[11,2,1,"","to_detection"]],"sigma.grammar.Selector":[[11,4,1,"","args"],[11,6,1,"","condition"],[11,4,1,"","parent"],[11,6,1,"","pattern"],[11,2,1,"","postprocess"]],"sigma.mitre":[[12,1,1,"","Attack"],[12,1,1,"","Tactic"],[12,1,1,"","Technique"]],"sigma.mitre.Attack":[[12,4,1,"","ATTACK_SINGLETON"],[12,4,1,"","ATTACK_URLS"],[12,4,1,"","SOURCE_TYPES"],[12,2,1,"","download"],[12,2,1,"","get_tactic"],[12,2,1,"","get_technique"],[12,2,1,"","load"],[12,4,1,"","tactics"],[12,4,1,"","techniques"]],"sigma.mitre.Tactic":[[12,4,1,"","id"],[12,4,1,"","title"],[12,6,1,"","url"]],"sigma.mitre.Technique":[[12,4,1,"","id"],[12,4,1,"","tactics"],[12,4,1,"","title"],[12,6,1,"","url"]],"sigma.schema":[[13,1,1,"","BaseCorrelation"],[13,1,1,"","Correlation"],[13,1,1,"","CorrelationGreaterThan"],[13,1,1,"","CorrelationGreaterThanEqual"],[13,1,1,"","CorrelationLessThan"],[13,1,1,"","CorrelationLessThanEqual"],[13,1,1,"","CorrelationRange"],[13,1,1,"","CorrelationSimpleCondition"],[13,1,1,"","CorrelationType"],[13,1,1,"","CountCorrelation"],[13,1,1,"","IncludeSchema"],[13,1,1,"","LowercaseString"],[13,1,1,"","Rule"],[13,1,1,"","RuleDetection"],[13,1,1,"","RuleDetectionFields"],[13,1,1,"","RuleDetectionList"],[13,1,1,"","RuleLevel"],[13,1,1,"","RuleLicense"],[13,1,1,"","RuleLogSource"],[13,1,1,"","RuleRelation"],[13,1,1,"","RuleRelationType"],[13,1,1,"","RuleStatus"],[13,1,1,"","RuleTag"],[13,1,1,"","Sigma"],[13,1,1,"","SimpleDate"],[13,1,1,"","TemporalCorrelation"]],"sigma.schema.BaseCorrelation":[[13,4,1,"","action"],[13,4,1,"","group_by"],[13,4,1,"","level"],[13,4,1,"","name"],[13,4,1,"","rule"],[13,4,1,"","timespan"],[13,4,1,"","type"]],"sigma.schema.CorrelationGreaterThan":[[13,4,1,"","gt"]],"sigma.schema.CorrelationGreaterThanEqual":[[13,4,1,"","gte"]],"sigma.schema.CorrelationLessThan":[[13,4,1,"","lt"]],"sigma.schema.CorrelationLessThanEqual":[[13,4,1,"","lte"]],"sigma.schema.CorrelationRange":[[13,6,1,"","maximum"],[13,6,1,"","minimum"],[13,4,1,"","range"]],"sigma.schema.CorrelationSimpleCondition":[[13,6,1,"","value"]],"sigma.schema.CorrelationType":[[13,4,1,"","EVENT_COUNT"],[13,4,1,"","TEMPORAL"],[13,4,1,"","VALUE_COUNT"]],"sigma.schema.CountCorrelation":[[13,4,1,"","condition"],[13,4,1,"","type"]],"sigma.schema.IncludeSchema":[[13,4,1,"","action"],[13,4,1,"","filename"],[13,2,1,"","load"]],"sigma.schema.Rule":[[13,1,1,"","Config"],[13,4,1,"","author"],[13,4,1,"","date"],[13,4,1,"","description"],[13,4,1,"","detection"],[13,4,1,"","falsepositives"],[13,4,1,"","fields"],[13,2,1,"","from_sigma"],[13,2,1,"","from_yaml"],[13,4,1,"","id"],[13,4,1,"","level"],[13,4,1,"","license"],[13,4,1,"","logsource"],[13,4,1,"","modified"],[13,2,1,"","parse_obj"],[13,4,1,"","references"],[13,4,1,"","related"],[13,4,1,"","status"],[13,4,1,"","tags"],[13,4,1,"","title"],[13,2,1,"","to_sigma"],[13,2,1,"","transform"]],"sigma.schema.Rule.Config":[[13,4,1,"","extra"],[13,4,1,"","schema_extra"]],"sigma.schema.RuleDetection":[[13,1,1,"","Config"],[13,4,1,"","GRAMMAR_PARSER"],[13,4,1,"","condition"],[13,6,1,"","expression"],[13,2,1,"","get_expression"],[13,2,1,"","lookup_expression"],[13,2,1,"","parse_grammar"],[13,2,1,"","post_init"],[13,6,1,"","rule"],[13,4,1,"","timeframe"],[13,2,1,"","transform"],[13,2,1,"","update_expression"],[13,2,1,"","validate_detection"]],"sigma.schema.RuleDetection.Config":[[13,4,1,"","extra"],[13,4,1,"","schema_extra"]],"sigma.schema.RuleDetectionFields":[[13,2,1,"","build_expression"]],"sigma.schema.RuleDetectionList":[[13,2,1,"","build_expression"]],"sigma.schema.RuleLevel":[[13,4,1,"","CRITICAL"],[13,4,1,"","HIGH"],[13,4,1,"","INFORMATIONAL"],[13,4,1,"","LOW"],[13,4,1,"","MEDIUM"],[13,2,1,"","to_severity"]],"sigma.schema.RuleLogSource":[[13,1,1,"","Config"],[13,4,1,"","category"],[13,4,1,"","definition"],[13,4,1,"","product"],[13,4,1,"","service"]],"sigma.schema.RuleLogSource.Config":[[13,4,1,"","extra"]],"sigma.schema.RuleRelation":[[13,1,1,"","Config"],[13,4,1,"","id"],[13,4,1,"","type"]],"sigma.schema.RuleRelation.Config":[[13,4,1,"","schema_extra"]],"sigma.schema.RuleRelationType":[[13,4,1,"","DERIVED"],[13,4,1,"","MERGED"],[13,4,1,"","OBSOLETES"],[13,4,1,"","RENAMED"]],"sigma.schema.RuleStatus":[[13,4,1,"","DEPRECATED"],[13,4,1,"","EXPERIMENTAL"],[13,4,1,"","STABLE"],[13,4,1,"","TEST"],[13,4,1,"","TESTING"],[13,4,1,"","UNSUPPORTED"]],"sigma.schema.RuleTag":[[13,6,1,"","name"],[13,6,1,"","namespace"],[13,2,1,"","validate"]],"sigma.schema.Sigma":[[13,2,1,"","load"]],"sigma.schema.TemporalCorrelation":[[13,4,1,"","type"]],"sigma.serializer":[[14,1,1,"","CommonSerializerSchema"],[14,1,1,"","LogSourceMatch"],[14,1,1,"","LogSourceRules"],[14,1,1,"","Serializer"],[14,1,1,"","TextQuerySerializer"],[15,0,0,"-","elastic"],[14,3,1,"","get_builtin_serializers"],[14,3,1,"","get_serializer_class"]],"sigma.serializer.CommonSerializerSchema":[[14,1,1,"","Config"],[14,4,1,"","base"],[14,4,1,"","description"],[14,4,1,"","logsource"],[14,4,1,"","name"],[14,4,1,"","transforms"]],"sigma.serializer.CommonSerializerSchema.Config":[[14,4,1,"","schema_extra"]],"sigma.serializer.LogSourceMatch":[[14,1,1,"","Config"],[14,4,1,"","category"],[14,2,1,"","compare"],[14,4,1,"","conditions"],[14,4,1,"","index"],[14,4,1,"","name"],[14,4,1,"","product"],[14,4,1,"","service"],[14,2,1,"","validate_detection"]],"sigma.serializer.LogSourceMatch.Config":[[14,4,1,"","schema_extra"]],"sigma.serializer.LogSourceRules":[[14,1,1,"","Config"],[14,4,1,"","defaultindex"],[14,2,1,"","match_rule"],[14,4,1,"","merging"],[14,4,1,"","rules"]],"sigma.serializer.LogSourceRules.Config":[[14,4,1,"","schema_extra"]],"sigma.serializer.Serializer":[[14,4,1,"","DEFAULT_FORMAT"],[14,4,1,"","Schema"],[14,2,1,"","apply_rule_transform"],[14,2,1,"","dumps"],[14,2,1,"","from_dict"],[14,2,1,"","from_yaml"],[14,2,1,"","load"],[14,2,1,"","merge_config"],[14,2,1,"","serialize"]],"sigma.serializer.TextQuerySerializer":[[14,1,1,"","Schema"],[14,2,1,"","dumps"],[14,2,1,"","serialize"],[14,4,1,"","transforms"]],"sigma.serializer.TextQuerySerializer.Schema":[[14,4,1,"","and_format"],[14,4,1,"","escape"],[14,4,1,"","escaped_characters"],[14,4,1,"","field_contains"],[14,4,1,"","field_endswith"],[14,4,1,"","field_equality"],[14,4,1,"","field_like"],[14,4,1,"","field_lookup"],[14,4,1,"","field_lookup_regex"],[14,4,1,"","field_match"],[14,4,1,"","field_not_empty"],[14,4,1,"","field_regex"],[14,4,1,"","field_startswith"],[14,4,1,"","grouping"],[14,4,1,"","keyword"],[14,4,1,"","list_separator"],[14,4,1,"","not_format"],[14,4,1,"","or_format"],[14,4,1,"","quote"]],"sigma.serializer.elastic":[[15,1,1,"","ElasticSecurityActionType"],[15,1,1,"","ElasticSecurityBaseAction"],[15,1,1,"","ElasticSecurityEmailAction"],[15,1,1,"","ElasticSecurityPagerDutyAction"],[15,1,1,"","ElasticSecurityRule"],[15,1,1,"","ElasticSecuritySlackAction"],[15,1,1,"","ElasticSecurityWebhookAction"],[15,1,1,"","EventQueryLanguage"]],"sigma.serializer.elastic.ElasticSecurityActionType":[[15,4,1,"","EMAIL"],[15,4,1,"","PAGERDUTY"],[15,4,1,"","SLACK"],[15,4,1,"","WEBHOOK"]],"sigma.serializer.elastic.ElasticSecurityBaseAction":[[15,1,1,"","Config"],[15,4,1,"","group"],[15,4,1,"","id"],[15,4,1,"","tags"],[15,2,1,"","to_rule_format"],[15,4,1,"","type"]],"sigma.serializer.elastic.ElasticSecurityBaseAction.Config":[[15,4,1,"","schema_extra"]],"sigma.serializer.elastic.ElasticSecurityEmailAction":[[15,1,1,"","Config"],[15,4,1,"","bcc"],[15,4,1,"","cc"],[15,4,1,"","message"],[15,4,1,"","subject"],[15,4,1,"","to"],[15,2,1,"","to_rule_format"],[15,4,1,"","type"]],"sigma.serializer.elastic.ElasticSecurityEmailAction.Config":[[15,4,1,"","schema_extra"]],"sigma.serializer.elastic.ElasticSecurityPagerDutyAction":[[15,1,1,"","Config"],[15,4,1,"","clazz"],[15,4,1,"","component"],[15,4,1,"","dedup_key"],[15,4,1,"","event_action"],[15,4,1,"","group"],[15,4,1,"","severity"],[15,4,1,"","source"],[15,4,1,"","summary"],[15,4,1,"","timestamp"],[15,2,1,"","to_rule_format"],[15,4,1,"","type"]],"sigma.serializer.elastic.ElasticSecurityPagerDutyAction.Config":[[15,4,1,"","schema_extra"]],"sigma.serializer.elastic.ElasticSecurityRule":[[15,4,1,"","DEFAULT_FORMAT"],[15,4,1,"","RULE_LANGUAGE_MAP"],[15,1,1,"","Schema"],[15,2,1,"","dumps"],[15,2,1,"","merge_config"],[15,4,1,"","schema"],[15,2,1,"","serialize"]],"sigma.serializer.elastic.ElasticSecurityRule.Schema":[[15,1,1,"","Config"],[15,4,1,"","actions"],[15,4,1,"","enable_rule"],[15,4,1,"","interval"],[15,4,1,"","max_signals"],[15,4,1,"","output_index"],[15,4,1,"","risk_default"],[15,4,1,"","risk_map"],[15,4,1,"","rule_type"],[15,4,1,"","severity_default"],[15,4,1,"","severity_map"],[15,4,1,"","timestamp_override"]],"sigma.serializer.elastic.ElasticSecurityRule.Schema.Config":[[15,4,1,"","extra"],[15,4,1,"","schema_extra"]],"sigma.serializer.elastic.ElasticSecuritySlackAction":[[15,1,1,"","Config"],[15,4,1,"","message"],[15,2,1,"","to_rule_format"],[15,4,1,"","type"]],"sigma.serializer.elastic.ElasticSecuritySlackAction.Config":[[15,4,1,"","schema_extra"]],"sigma.serializer.elastic.ElasticSecurityWebhookAction":[[15,1,1,"","Config"],[15,4,1,"","body"],[15,2,1,"","to_rule_format"],[15,4,1,"","type"]],"sigma.serializer.elastic.ElasticSecurityWebhookAction.Config":[[15,4,1,"","schema_extra"]],"sigma.serializer.elastic.EventQueryLanguage":[[15,1,1,"","Schema"],[15,2,1,"","serialize"],[15,4,1,"","transforms"]],"sigma.serializer.elastic.EventQueryLanguage.Schema":[[15,1,1,"","Config"],[15,4,1,"","and_format"],[15,4,1,"","escape"],[15,4,1,"","escaped_characters"],[15,4,1,"","field_contains"],[15,4,1,"","field_endswith"],[15,4,1,"","field_equality"],[15,4,1,"","field_like"],[15,4,1,"","field_lookup"],[15,4,1,"","field_lookup_regex"],[15,4,1,"","field_match"],[15,4,1,"","field_not_empty"],[15,4,1,"","field_regex"],[15,4,1,"","field_startswith"],[15,4,1,"","grouping"],[15,4,1,"","keyword"],[15,4,1,"","list_separator"],[15,4,1,"","not_format"],[15,4,1,"","or_format"],[15,4,1,"","prepend_result"],[15,4,1,"","quote"],[15,4,1,"","rule_separator"]],"sigma.serializer.elastic.EventQueryLanguage.Schema.Config":[[15,4,1,"","schema_extra"]],"sigma.transform":[[16,1,1,"","AddTags"],[16,1,1,"","ContainsToMatch"],[16,1,1,"","ExpressionType"],[16,1,1,"","FieldFuzzyMap"],[16,1,1,"","FieldMap"],[16,1,1,"","FieldMatchReplace"],[16,1,1,"","Transformation"]],"sigma.transform.AddTags":[[16,1,1,"","Schema"],[16,2,1,"","transform_rule"]],"sigma.transform.AddTags.Schema":[[16,1,1,"","Config"],[16,4,1,"","tags"],[16,4,1,"","type"]],"sigma.transform.AddTags.Schema.Config":[[16,4,1,"","extra"],[16,4,1,"","schema_extra"]],"sigma.transform.ContainsToMatch":[[16,2,1,"","transform_expression"]],"sigma.transform.ExpressionType":[[16,4,1,"","CONTAINS"],[16,4,1,"","ENDSWITH"],[16,4,1,"","STARTSWITH"]],"sigma.transform.FieldFuzzyMap":[[16,1,1,"","Schema"],[16,2,1,"","transform_expression"]],"sigma.transform.FieldFuzzyMap.Schema":[[16,1,1,"","Config"],[16,4,1,"","mapping"],[16,4,1,"","skip_unknown"],[16,4,1,"","type"]],"sigma.transform.FieldFuzzyMap.Schema.Config":[[16,4,1,"","extra"],[16,4,1,"","schema_extra"]],"sigma.transform.FieldMap":[[16,1,1,"","Schema"],[16,2,1,"","transform_expression"]],"sigma.transform.FieldMap.Schema":[[16,1,1,"","Config"],[16,4,1,"","mapping"],[16,4,1,"","skip_unknown"],[16,4,1,"","type"]],"sigma.transform.FieldMap.Schema.Config":[[16,4,1,"","extra"],[16,4,1,"","schema_extra"]],"sigma.transform.FieldMatchReplace":[[16,1,1,"","Schema"],[16,4,1,"","VALID_TYPES"],[16,2,1,"","transform_expression"]],"sigma.transform.FieldMatchReplace.Schema":[[16,1,1,"","Config"],[16,4,1,"","expression"],[16,4,1,"","field"],[16,4,1,"","pattern"],[16,4,1,"","target"],[16,4,1,"","type"]],"sigma.transform.FieldMatchReplace.Schema.Config":[[16,4,1,"","extra"],[16,4,1,"","schema_extra"]],"sigma.transform.Transformation":[[16,1,1,"","Schema"],[16,2,1,"","enumerate_builtin"],[16,2,1,"","lookup_class"],[16,2,1,"","transform_expression"],[16,2,1,"","transform_rule"]],"sigma.transform.Transformation.Schema":[[16,1,1,"","Config"],[16,2,1,"","load"],[16,4,1,"","type"]],"sigma.transform.Transformation.Schema.Config":[[16,4,1,"","extra"]],"sigma.util":[[17,1,1,"","CopyableSchema"]],"sigma.util.CopyableSchema":[[17,2,1,"","copy_schema"],[17,4,1,"","schema_extra"]],sigma:[[2,0,0,"-","cli"],[10,0,0,"-","errors"],[11,0,0,"-","grammar"],[12,0,0,"-","mitre"],[13,0,0,"-","schema"],[14,0,0,"-","serializer"],[16,0,0,"-","transform"],[17,0,0,"-","util"]]},objnames:{"0":["py","module","Python module"],"1":["py","class","Python class"],"2":["py","method","Python method"],"3":["py","function","Python function"],"4":["py","attribute","Python attribute"],"5":["py","exception","Python exception"],"6":["py","property","Python property"]},objtypes:{"0":"py:module","1":"py:class","2":"py:method","3":"py:function","4":"py:attribute","5":"py:exception","6":"py:property"},terms:{"0":[2,13,15],"001":13,"03":21,"07":13,"1":18,"10":15,"100":[13,15,21],"12":13,"1234":13,"14":21,"15":13,"159489a390df":13,"2":18,"2019":13,"2020":21,"2021":13,"20t14":21,"23":21,"25":15,"256":13,"28":21,"28b9":13,"3":[18,21],"30":13,"31":13,"35":[15,21],"382748":21,"3d":13,"4":18,"4344":13,"5":[15,18,21],"535":13,"5m":[13,15,21],"65":[13,15,21],"75":15,"7aa7009a":13,"8":2,"8c1f":13,"95":[15,21],"abstract":[11,12,14,20],"byte":11,"case":[13,14,15,16],"catch":2,"class":[1,2,4,11,12,13,14,15,16,17,18,19,20,21],"default":[14,15,16,20,21],"do":19,"enum":[13,15,16],"final":22,"function":[1,13],"import":[1,13,18,19],"int":[10,11,13,15,18],"long":13,"new":[11,13,14,15,16,19,22],"null":[11,15],"return":[1,2,11,13,14,15,16,18,19,22],"short":13,"static":14,"super":16,"switch":13,"true":[11,14,15,18,21],"while":[11,13,21],A:[1,2,10,11,13,14,15,16,19,21,22],AND:[11,13,14,15,19,22],And:11,As:[16,19,21],At:21,By:21,For:[1,19,20,21],If:[13,14,15,16,21,22],In:14,It:[13,18,21],NO:15,NOT:[14,15],No:13,OR:[11,13,14,15,19],One:14,Or:11,The:[1,10,11,13,14,15,16,18,19,20,21,22],Their:21,There:[10,11,21],These:[11,13],To:[2,19],With:20,__init__:16,a53a02b997935fd8eedcb5f7abab9b9f:13,abc:[12,14,16],abil:20,abov:[15,19,21,22],accept:16,access:[18,19],accord:[2,13,22],across:[14,15],action:[13,15,22],activ:[13,18,20],ad:[2,19,21],add:[2,14,16],add_command:2,add_tag:16,addtag:16,adjust:21,after:[10,13,18],against:[14,16,22],alert:[13,15,21],alia:13,aliased_group:2,all:[10,11,13,14,15,16,19,21,22],allow:[13,16,18,19,21],almost:13,along:[1,20],alongsid:19,also:[1,13,14,16,22],alwai:[10,14],amount:13,ampliasecur:13,an:[4,10,11,13,14,15,16,18,19,20,21,22],analysi:13,analyst:13,and_format:[14,15],ani:[2,11,13,14,15,16,17,18,19,21,22],anoth:[13,14,15,20,22],anymor:13,api:[20,21],append:[14,19],appli:[13,14,15,18,21,22],applic:[13,15],apply_rule_transform:14,ar:[1,10,11,13,14,15,18,19,21,22],arbitrari:[13,14,18,22],aren:[13,16],arg:[2,11,13,19,20],argument:[2,10,14,18,20],articl:13,asid:[14,15],assist:1,associ:[13,14],att:20,attach:2,attack:[12,13,16,19],attack_singleton:12,attack_url:12,attr:2,attribut:[2,13],author:[1,13],automat:2,avail:21,back:[1,13,14,16],backend:[16,20,22],bare:21,base64:11,base64_modifi:11,base64fieldequ:11,base64offset:11,base64offset_modifi:11,base:[2,4,10,11,12,13,14,15,16,17,18,19,20],base_class:14,basecorrel:13,basemodel:[4,11,12,13,14,15,16],basi:13,basic:[14,18],bcc:[15,21],becaus:13,been:21,being:[16,19],below:[19,21,22],between:[16,20],beyond:21,blog:13,bodi:[15,21],bool:[11,14,15,16,18],both:[19,21,22],bound:13,brief:13,brows:20,build:[11,13,14],build_express:13,build_grammar_pars:11,build_key_value_express:11,built:[1,14,16,20,21],builtin:14,cach:20,calebstewart:20,call:[2,16,19],callabl:11,callback:[2,11],camelcas:16,can:[1,13,14,16,18,19,20,21,22],categori:[13,14,15,22],categoris:13,caus:14,cc:[15,21],cd:20,chain:18,chang:[2,19,20],charact:[13,14,15],check:11,ck:20,classmethod:[11,12,13,14,16,17],classnam:[14,16,20,22],classvar:[11,12,13,14,15],clazz:[15,21],cli:[0,1,20],click:2,clone:20,clussvc:13,cmd:22,cmd_name:2,code:22,collaps:11,collect:13,collis:13,column:10,com:[12,13,15,20,21],combin:[10,13,14,15,20,21],come:[1,21],command:[2,3,13,18,19,22],command_class:2,command_lin:16,commandlin:[13,16,22],commandwithverbos:2,common:[13,14,16,20,22],commonli:16,commonserializerschema:[14,18],compani:[15,21],compar:[11,14,16,22],comparison:[11,16],compat:22,complet:[14,19],completed_modifi:10,compliant:[13,15],compon:[15,21],condit:[1,10,11,13,14,16,18,19,20,21,22],conditionsyntaxerror:10,config:[10,13,14,15,16,18,19],configur:[1,2,14,15,16,20,21],conflict:21,conform:[14,21],conjunct:13,connector:[15,21],consid:13,constrainedstrvalu:13,construct:[1,11,13,14,15,16,20,22],contain:[1,10,13,14,15,16,18,22],containstomatch:16,context:[2,15],control:[14,21],convers:[10,13,20],convert:[1,2,11,13,14,15,16,18,20,21,22],copy_schema:[17,18,19],copyableschema:[14,15,17,18,19],core:[1,2,11,13],coreexpress:11,correct:[14,15],correl:[10,13],correlationgreaterthan:13,correlationgreaterthanequ:13,correlationlessthan:13,correlationlessthanequ:13,correlationrang:13,correlationsimplecondit:13,correlationtyp:13,correspond:21,could:[13,14,20,21,22],countcorrel:13,cover:13,creat:[2,13,20,21,22],creator:13,credenti:13,credential_access:13,criteria:[13,14],critic:[13,15,21],cti:12,ctx:2,current:[10,13,14,15],custom:[2,13,14,16,18,19,20,21,22],custom_tag1:16,custom_tag2:16,custom_tag:19,customseri:[18,22],customtransform:[16,19],dashboard:13,data:[12,13,15,18,19,20,22],date:[12,13,15],datetim:[13,15],dd:13,declar:[2,13],decor:2,dedup_kei:[15,21],def:[16,18,19],default_format:[14,15],defaultindex:[14,15,22],defer:20,defin:[1,11,13,14,15,16,18,19,21,22],definit:[4,11,13,14,16,18,20],depend:[14,22],deploy:4,deprec:13,deriv:13,describ:[13,21],descript:[13,14,15,16,22],detail:[1,12,14,21],detect:[1,10,11,13,14,15,16,18,20,22],develop:[13,20],dict:[2,4,11,13,14,15,16,17,22],dictionari:[1,13,14,15,21],differ:[14,19,21,22],direct:11,directli:[2,11,13,14,20,21,22],disabl:21,disk:[1,13],displai:13,doc:[20,21],document:[10,13,21],doe:[13,19,21,22],don:[11,19],dot:13,download:[12,20],due:21,dump:[1,10,14,15,20],duplic:[10,18,19],duplicaterulenameerror:10,dure:[1,10,16,21],e96a73c7bf33a464c510ede582318bf2:13,e:[13,14,15,19,20,21],each:[11,14,16,19,21,22],easi:1,easier:18,easili:[18,19],editor:13,either:[11,13,14,15,16,19],elast:[1,2,14,22],elasticdeploymentspec:4,elasticsearch:15,elasticsecurityact:21,elasticsecurityactiontyp:15,elasticsecuritybaseact:15,elasticsecurityemailact:15,elasticsecuritypagerdutyact:15,elasticsecurityrul:[4,15],elasticsecurityslackact:15,elasticsecuritywebhookact:15,elif:19,els:19,email:[15,21],empti:[13,14],enabl:[15,18,21],enable_rul:[15,21],encod:11,end:[11,14,15],endswith:[13,15,16],engin:[14,15],enrich:13,enter:20,enterpris:12,entir:[16,19],entri:13,enumer:[13,15,16],enumerate_builtin:16,environ:20,eql:[1,14,15,20,22],equal:[11,14,15,16],equival:14,error:[0,1,14],error_wrapp:10,es:[15,20,21],escap:[14,15],escaped_charact:[14,15],especi:22,etc:13,evalu:[11,13,16],even:13,event:[13,15,22],event_act:[15,21],event_count:13,eventquerylanguag:15,everi:[14,21],everyth:13,ex:[13,16,22],exact:19,exampl:[13,14,15,16,17,19,20,21,22],example_extra:[17,18,19],except:[2,10,11,13,14,16],execut:[11,16,21],exist:[2,13,14,15],exit:20,expect:[10,13],experiment:13,explicit:[16,22],explicitli:16,express:[11,13,14,15,16,18,20],expressiontyp:16,extend:[16,18,19],extra:[13,15,16,18,19,20,21,22],extra_data:[13,16],extra_tag:19,extrem:18,ey:11,f:[1,19],facilit:[11,14],fail:10,failed_modifi:10,fals:[11,13,14,15,16],falseposit:13,feel:13,few:[21,22],field:[1,10,11,13,14,15,16,18,19,21,22],field_contain:[14,15],field_endswith:[14,15],field_equ:[14,15],field_fuzzy_map:16,field_lik:[14,15],field_lookup:[14,15],field_lookup_regex:[14,15],field_map:[16,20,22],field_match:[14,15],field_not_empti:[14,15],field_regex:[14,15],field_startswith:[14,15],fieldcomparison:[11,16],fieldcontain:[11,16],fieldendswith:[11,16],fieldequ:11,fieldfuzzymap:16,fieldlik:11,fieldlookup:11,fieldlookupregex:11,fieldmap:16,fieldmatchreplac:16,fieldnotempti:11,fieldregex:11,fieldstartswith:[11,16],fieldtransform:16,file:[1,10,13,14,15,20,21,22],filenam:[13,20],filepath:13,filter:[13,15],fine:13,fire:[15,21],first:[13,14,21,22],five:13,florian:13,fmt:10,follow:[13,14,15,16,18,21,22],forbid:[15,16],form:21,format:[10,13,14,15,16,19,20,21,22],former:21,forward:[13,21],found:10,framework:[1,12],free:[13,21],frequent:13,from:[1,11,13,14,15,16,18,19,20,21,22],from_dict:14,from_pars:11,from_sigma:13,from_yaml:[1,13,14],full:[13,22],fulli:[11,14,16,22],further:[13,14,21],futur:[18,19,20],fuzzi:2,fuzzyaliasedgroup:2,fuzzywuzzi:2,g:[13,14,15,21],gener:[10,13,14,16,21],get_builtin_seri:14,get_command:2,get_express:13,get_serializer_class:14,get_tact:12,get_techniqu:12,git:20,github:[13,20],githubusercont:12,given:[2,10,11,13,14,15,16,19,20,22],glob:[13,14,15],global:13,go:11,grab:11,grammar:[0,1,13,16,19,20],grammar_pars:13,group:[2,11,13,14,15,16,21],group_bi:13,gt:13,gte:13,ha:[13,16],had:13,handl:[1,11,13],have:[13,14,21],hello:18,help:[14,20],helper:10,here:[11,21],high:[13,15,19,21],highli:13,highlight:[14,15],home:13,how:[14,15,19,22],howev:22,http:[12,13,20],huge:13,hyphen:13,i:[11,19],id:[12,13,15,21],identifi:[10,11,13,14],ignor:[14,16],ignore_skip:[14,15],imag:[13,16,22],immedi:[2,13],imphash:13,implement:[1,11,16,18,19,20],importlib:[12,14],incid:13,includ:13,includeschema:13,incorrect:10,index:[14,15,20,21,22],indic:[13,14,15,22],individu:[16,19],inform:[13,15,16,21],ingest:[1,15,20,21],inherit:[14,18,19,22],initi:14,inlin:[1,16],input:14,inspect:[13,14],instanc:[11,14,16,18,19],instanti:[13,19,22],instead:[11,13,21],integ:[13,21],intend:13,interact:[11,20],interest:13,interfac:[3,13],intern:[13,14,19],interv:[15,21],invalid:10,invalidfieldvalueerror:10,invalidmodifiercombinationerror:10,invoc:2,invok:2,isinst:[18,19],issu:13,item:[14,15,21],iter:[13,14],its:13,itself:14,join:[14,22],json:[1,12,13,14,15,20,21,22],keep:13,kei:[11,19],keyword:[2,11,13,14,15],keywordsearch:11,known:13,kql:[1,20],kwarg:[2,13],languag:[1,15,22],last:13,lastli:1,latter:[14,21],lead:13,least:[21,22],leav:11,length:14,letter:13,level:[13,15,19,21],licens:13,like:[10,11,14,15,19],line:[3,10,13],lineno:10,link:13,list:[1,2,4,10,11,12,13,14,15,16,18,19,20,21,22],list_of_indic:14,list_separ:[14,15],liter:[11,13,14,15,16],load:[1,12,13,14,16,18,20],load_rules_from_path:4,loc:11,local:14,locat:12,log:[2,10,13,14,15,20],logic:[11,13,14,15,21,22],logicaland:[11,19],logicalexpress:11,logicalnot:11,logicalor:[11,19],logsourc:[13,14,15,21,22],logsourcematch:14,logsourcerul:[14,15],look:19,lookup:[11,12,13,16],lookup_class:16,lookup_express:13,low:[13,15,21],lower:13,lowercasestr:13,lt:13,lte:13,lucen:15,made:[13,14],mai:[13,14,18,19,20,22],main:[4,11,12,13,14,15,16],mainli:[10,14],major:1,make:[1,19],malici:13,manag:20,manual:13,map:[1,15,16,21,22],master:12,match:[2,11,13,14,15,16,19,21,22],match_replac:16,match_rul:14,max:13,max_sign:[15,21],maximum:[13,21],mean:[19,22],meant:13,medium:[13,15,21],memori:[1,13,14,22],merg:[13,14,15,22],merge_config:[14,15],messag:[10,15,20,21],method:[1,10,13,14,16,18,19],mind:20,minimum:[13,14],miss:22,missingcorrelationrul:10,missingidentifi:13,mitr:[0,1,2,20],mm:13,mobil:12,model:[18,19],modif:[1,16,19],modifi:[1,10,11,13,14,16,19,20,21],modified_rul:14,modul:[0,1,2,14,16,19,20,22],more:[1,10,13,14],morph:21,most:[10,16],mostli:[18,21],multipl:[10,14,15,22],multiplecorrelationerror:10,must:[11,14,15,16,18,19,21,22],my:[19,21,22],my_command_line_field:22,my_config:18,my_custom:15,my_custom_tag:15,my_imag:22,n:15,name:[2,10,13,14,15,16,22],namespac:13,nativ:[1,13],necessari:[13,14,22],need:[11,13,16],nest:13,never:13,newlin:14,nocorrelationdocu:10,noisi:13,non:19,none:[2,10,11,12,13,14,15,16],normal:[13,16,19],not_format:[14,15],notabl:13,note:11,notif:15,number:[13,14,21],numer:13,o:20,obj:13,object:[1,2,13,14,16,17,19,21,22],obsolet:13,occur:13,off:14,offici:21,oh:15,omit:19,one:[10,13,14,16,21],ones:11,onli:[14,18,21],oper:[11,16],oppos:11,option:[2,10,11,12,13,14,15,16,18,19,20,21,22],or_format:[14,15],order:22,organ:14,orient:13,origin:[14,16],os:13,other:[10,13,14,21,22],other_config:18,our:[14,15],output:[14,15,21,22],output_index:[15,21],outsid:13,over:14,overrid:20,own:[18,19,20,21],packag:[0,13,19,20,22],page:20,pagerduti:[15,21],pair:[11,19],paper:13,paramet:[2,10,14,15,16],parent:[2,11,16],parentimag:[13,16],pars:[1,11,13],parse_grammar:13,parse_obj:13,parseexcept:10,parser:[11,13],parseresult:11,parsing_error:10,parti:20,pass:[2,14,22],path:[4,12,13,14,16,22],pathlib:[4,12,13,14],pathlik:13,pattern:[11,13,14,15,16],per:21,perform:[21,22],period:13,pip:20,platform:[1,13],poetri:20,posit:13,possibl:[13,14,19,21],post_init:13,postprocess:11,pre:12,predefin:13,prepend:15,prepend_result:15,present:13,pretti:[14,15],previous:13,print:[1,13],prior:[2,13,18,21,22],privat:13,process:[10,11,14,16],process_cr:[1,13,14,15,22],produc:[13,14,21],product:[13,14,15,22],project:20,prompt:13,properti:[10,11,12,13,14,18,19,21],propos:13,provid:[2,10,13,14,15,16,18,19,20,21,22],pseudo:22,pull:13,pydant:[1,4,10,11,12,13,14,15,16,18,19],pypars:[1,10,11,13],pysigma:11,python:[1,11,13,14,16,21,22],qualifi:[14,16,22],queri:[1,13,14,15,22],quot:[14,15],r:18,rais:[10,13,14,16],rang:13,rare:13,rate:13,raw:[12,14,21],re:1,reaction:13,read:13,reason:13,recommend:[13,18],recurs:[16,19],refer:[11,13,14,19],regardless:14,regex:[11,14,15,16],regist:2,regular:[11,13,16],rel:[19,21],relat:[13,21],relationship:13,relev:13,remain:13,renam:[13,21],replac:[11,13,16],repositori:20,repr:18,repres:[11,13,14,15,18],represent:[13,14],reproduc:13,request:[10,13,14],requir:[13,14,15,19,21,22],research:13,resolv:[11,13],respect:[14,21],rest:21,restrict:14,result:[11,13,15],retriev:[13,14],reus:16,review:13,right:2,rip:11,risk:[15,21],risk_default:[15,21],risk_map:[15,21],root:22,roth:13,rule:[1,4,10,11,13,14,15,16,20,22],rule_language_map:15,rule_path:4,rule_separ:15,rule_typ:15,ruledetect:[11,13],ruledetectionfield:[13,14],ruledetectionlist:13,rulelevel:13,rulelicens:13,rulelogsourc:13,rulerel:13,rulerelationtyp:13,rulestatu:13,ruletag:[13,15,16,19],rulevalidationerror:10,runtim:[18,19],s0005:13,s:[1,11,13,14,15,21,22],safe:13,same:[2,10,11,13,14,19,21],sampl:22,save:[1,12,13],schema:[0,1,2,4,10,11,14,15,18,19,20,21,22],schema_extra:[13,14,15,16,17,18,19],scheme:13,search:[11,13,14,20],section:[13,14],secur:[13,15,22],see:[1,14,19,21],seen:14,select:14,selection1:13,selection2:13,selector:[11,14],self:[16,18,19],send:[13,15],sentenc:13,separ:[13,14,15],sequenc:2,serial:[0,1,4,10,11,13,16,19,20],serializ:[1,13],serializerclass:18,serializernotfound:10,serializervalidationerror:10,servic:[13,14,22],set:[2,13,15,21],setup:[19,20],sever:[13,15,21],severity_default:[15,21],severity_map:[15,21],shell:20,shortcut:[2,11],should:[11,13,14,16,18,20,21],shouldn:13,show:[19,20],shrug:21,siem:[15,21],sigma:[18,19,21,22],sigmaerror:10,sigmahq:13,sigmavalidationerror:10,signal:[15,21],similar:14,simpl:[13,18],simpled:13,simpli:[14,16],singl:[13,14,15,19,21],singular:13,situat:11,skip:10,skip_unknown:16,skiprul:[10,14,16],slack:[15,21],slightli:21,snake_cas:16,so:[16,19,20],solut:21,some:[13,14,18],someon:21,someoneels:21,someth:21,somewher:11,sourc:[13,14,15,16,20,21],source_typ:12,space:13,spdx:13,special:[13,19],specif:[10,11,13,16,19,20,21,22],specifi:[10,12,13,14,21,22],splunk:14,stabl:13,standard:20,start:[11,14,15],startswith:[15,16],state:13,statement:19,statu:13,stdout:20,still:13,str:[2,4,10,11,12,13,14,15,16,17,18,19],straight:21,straightforward:19,string:[11,13,14,15,16,21,22],stringcontain:15,structur:[11,16,22],sub:[2,16],subclass:10,subject:[15,21],submodul:[0,20],subpackag:[0,20],substitut:16,suitabl:21,summari:[15,21],support:14,suppos:13,swap:19,syntax:[10,13,14,15,21],system:[13,20,22],t1003:13,t12345:[16,19],t1234:13,t:[11,13,16,19],tactic:12,tactit:12,tag:[13,15,16,19,21],take:[2,18,19,22],taken:11,target:[14,16,22],technic:13,techniqu:[12,13],tempor:13,temporalcorrel:13,term:13,test:[11,13,14,15,16],text:[14,15],textqueryseri:[14,15],them:[1,2,13],themselv:21,thi:[1,2,10,11,13,14,15,16,18,19,20,21,22],thing:[11,14],third:20,threat:15,three:22,threshold:15,through:[1,18],time:[15,21],timefram:13,timespan:13,timestamp:[15,21],timestamp_overrid:[15,21],titl:[1,12,13,16,19],title_format:19,to_detect:11,to_field_with_modifi:11,to_rule_format:15,to_sever:13,to_sigma:[1,13],token:11,top:21,touch:22,traceback:2,transform:[0,1,2,10,11,13,14,15,20,21],transform_express:[16,19],transform_rul:[16,19],transformvalidationerror:10,transorm:13,travers:[12,14],tree:11,trigger:[13,15,21],tune:13,tupl:[11,14,16],tweet:13,two:[11,16,19,21],type:[10,11,13,14,15,16,18,19,21,22],unalt:16,unchang:11,under:20,underscor:13,understand:11,unhandl:2,union:[2,11,12,13,14,15,18],uniqu:13,unknownidentifiererror:10,unknownmodifiererror:10,unknownrulenameerror:10,unknowntransform:10,unspecifi:15,unsupport:[10,13],unsupportedserializerformat:[10,14],up:[2,12],updat:[20,22],update_express:13,upload:21,url:12,us:[1,2,10,13,14,15,16,18,19,20,21,22],usag:[20,21],useless:18,user:[18,19],utf16_modifi:11,utf16be_modifi:11,utf16l:11,utf16le_modifi:11,util:[0,1,14,15,18,19,21,22],uuid:13,v:[13,14],valid:[1,2,10,11,13,14,16,20,21,22],valid_typ:16,validate_detect:[13,14],validationerror:10,valu:[10,11,13,14,15,16,19,21],value_count:13,varieti:[1,14],variou:20,verbos:2,version:[2,16,19,21],via:[18,19,22],view:[18,19,22],virtual:20,visit:11,wa:[10,13,21],wai:[2,10,13],wce:13,we:16,webhook:[15,21],well:[18,19,20],what:[11,13],when:[10,11,14,15,19,20,21,22],where:21,whether:[14,15],which:[1,11,13,14,15,16,18,19,20,21,22],who:[18,19],whole:[13,16,19],wide_modifi:11,wiki:13,wildcard:[11,16],win_susp_net_execut:1,window:[1,13,14,15,22],windows_process_cr:22,within:[14,16,19,21,22],without:[13,22],world:18,would:21,write:[13,22],written:13,www:13,yaml:[1,10,13,14,15,16,19,20,22],yield:[14,16],yml:[1,13,20,21],you:[1,11,13,14,16,18,19,20,21,22],your:[14,15,16,18,19,20,21,22],yyyi:13},titles:["sigma","sigma package","sigma.cli package","sigma.cli.converter module","sigma.cli.elastic module","sigma.cli.list module","sigma.cli.mitre module","sigma.cli.schema module","sigma.cli.transform module","sigma.cli.validate module","sigma.errors module","sigma.grammar module","sigma.mitre module","sigma.schema module","sigma.serializer package","sigma.serializer.elastic module","sigma.transform package","sigma.util module","Creating Rule Serializers","Creating Rule Transformations","Welcome to Python Sigma\u2019s documentation!","Elastic Serializers","Serializer Configurations"],titleterms:{"class":22,action:21,base:22,built:22,cli:[2,3,4,5,6,7,8,9],command:20,configur:[18,19,22],content:20,convert:3,creat:[18,19],definit:22,document:20,elast:[4,15,21],eql:21,error:10,event:21,exampl:18,express:19,grammar:11,indic:20,instal:20,interfac:20,languag:21,line:20,list:5,log:22,mitr:[6,12],modul:[3,4,5,6,7,8,9,10,11,12,13,15,17],packag:[1,2,14,16],python:20,queri:21,rule:[18,19,21],s:20,schema:[7,13,16],secur:21,serial:[14,15,18,21,22],sigma:[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,20],sourc:22,submodul:[1,2,14],subpackag:1,tabl:20,transform:[8,16,18,19,22],util:17,valid:9,welcom:20}})