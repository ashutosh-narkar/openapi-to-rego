package opa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/getkin/kin-openapi/openapi3"
)

var (
	pathParamRE    = regexp.MustCompile("{[.;?]?([^{}*]+)\\*?}")
	opNameToSymbol = map[string]string{
		"eq":         " = ",
		"lt":         " < ",
		"gte":        " >= ",
		"membership": " = ",
		"negation":   "not ",
	}
)

const (
	// OAS Extension to generate a Rego rule that returns list of field names in an object to filter
	oasSecExtRegoFieldFilter = "x-security-rego-field-filter"

	// OAS Extension to generate a Rego rule that returns a filtered list of objects
	oasSecExtRegoListFilter = "x-security-rego-list-filter"

	// OAS Extension to generate a Rego rule that overwrites value of a field in an object
	oasSecExtRegoOverwriteFilter = "x-security-rego-overwrite-filter"

	// OAS Extension to generate a Rego rule that returns a boolean decision
	oasSecExtRegoBooleanFilter = "x-security-rego-boolean-filter"

	tokenPrefix        = "token"
	inputPrefix        = "input"
	pathTemplatePrefix = "$"

	helperRuleName = "allow"
)

var regoTemplate = `package %s
default allow = false

token = {"payload": payload} { io.jwt.decode(input.token, [_, payload, _]) }{{range .}}{{ if .FieldFilter }}

filter = {{.FieldFilter}} {
  input.path = {{.Path}}
  input.method = {{.Method}}
  {{- with .Scopes}}
  {{- range .}}
  token.payload.scopes["{{.}}"]
  {{- end}}
  {{- end}}
}{{else if .ListFilter}}

list_filter[x] {
  input.path = {{.Path}}
  input.method = {{.Method}}
  x := input.{{.ListFilter.Source}}[_]
  {{- with .ListFilter.Expressions}}
  {{- range .}}
  {{.}}
  {{- end}}
  {{- end}}
}{{else if .OverwriteFilter}}
{{if eq .OverwriteFilter.Negated true}}
response["{{.OverwriteFilter.Field}}"] = {{.OverwriteFilter.Value}} {
    not {{.OverwriteFilter.HelperRuleName}}
}

response["{{.OverwriteFilter.Field}}"] = input.object.{{.OverwriteFilter.Field}} {
    {{.OverwriteFilter.HelperRuleName}}
}{{else}}
response["{{.OverwriteFilter.Field}}"] = {{.OverwriteFilter.Value}} {
    {{.OverwriteFilter.HelperRuleName}}
}

response["{{.OverwriteFilter.Field}}"] = input.object.{{.OverwriteFilter.Field}} {
    not {{.OverwriteFilter.HelperRuleName}}
}{{end}}{{ $helper := .OverwriteFilter.HelperRuleName }} {{$path := .Path}} {{$method := .Method}}
{{range .OverwriteFilter.Expressions}}
{{$helper}} = true {
  input.path = {{$path}}
  input.method = {{$method}}
{{- range .}}
  {{.}}
{{- end}}
}
{{end}}{{else if .BooleanFilter}} {{$path := .Path}} {{$method := .Method}}
{{range .BooleanFilter.Expressions}}

allow = true {
  input.path = {{$path}}
  input.method = {{$method}}
{{- range .}}
  {{.}}
{{- end}}
}{{end}}{{else}}

allow = true {
  input.path = {{.Path}}
  input.method = {{.Method}}
}{{end}}{{end}}`

// PolicySchema defines the policy to generate
type PolicySchema struct {
	Path            string
	Method          string
	Scopes          []string
	FieldFilter     string
	ListFilter      *policySchemaListFilter
	OverwriteFilter *policySchemaOverwriteFilter
	BooleanFilter   *policySchemaBooleanFilter
}

// policySchemaListFilter defines the policy to generate from a list filter
type policySchemaListFilter struct {
	Source      string
	Operations  []operation
	Expressions []string
}

// policySchemaOverwriteFilter defines the policy to generate from a overwrite filter
type policySchemaOverwriteFilter struct {
	Field          string
	Value          interface{}
	Negated        bool
	Rules          []rule
	HelperRuleName string
	Expressions    [][]string
}

// policySchemaBooleanFilter defines the policy to generate from a boolean filter
type policySchemaBooleanFilter struct {
	Rules       []rule
	Expressions [][]string
}

type rule struct {
	Operations []operation
}

type operation map[string][]interface{}

type extensionDefinition map[string][]string

// Generate generates the Rego policy given a OpenAPI 3 spec
func Generate(swagger *openapi3.Swagger, packageName string) (string, error) {

	schemas := []PolicySchema{}

	for path, item := range swagger.Paths {
		for method, operation := range item.Operations() {

			// check for "x-security-rego-field-filter" extension
			if val, ok := operation.ExtensionProps.Extensions[oasSecExtRegoFieldFilter]; ok {

				// security requirement object needs to exist as the "x-security-rego-field-filter"
				// extension references it
				// TODO: Update the filter to support operations
				if operation.Security == nil {
					return "", fmt.Errorf("OpenAPI spec does not specify a Security Requirement Object")
				}

				securitySchemes := getSecuritySchemes(operation.Security)

				data, ok := val.(json.RawMessage)
				if !ok {
					return "", fmt.Errorf("OpenAPI extensions: type assertion error")
				}
				var extensionDefinitions []extensionDefinition
				err := json.Unmarshal(data, &extensionDefinitions)
				if err != nil {
					return "", err
				}

				for _, extensionDefinition := range extensionDefinitions {
					for schemeName, maskFields := range extensionDefinition {

						var scopes []string
						var ok bool
						if scopes, ok = securitySchemes[schemeName]; !ok {
							return "", fmt.Errorf("Unknown security scheme %v in OpenAPI extension", schemeName)
						}

						schema := PolicySchema{
							Path:        convertOASPathToParsedPath(path),
							Method:      strconv.Quote(method),
							Scopes:      scopes,
							FieldFilter: getFormattedMaskFields(maskFields),
						}
						schemas = append(schemas, schema)
					}
				}
			}

			// check for "x-security-rego-list-filter" extension
			if val, ok := operation.ExtensionProps.Extensions[oasSecExtRegoListFilter]; ok {
				data, ok := val.(json.RawMessage)
				if !ok {
					return "", fmt.Errorf("OpenAPI extensions: type assertion error")
				}

				var policySchemaListFilters []policySchemaListFilter
				err := json.Unmarshal(data, &policySchemaListFilters)
				if err != nil {
					return "", err
				}

				for _, p := range policySchemaListFilters {
					expressions := []string{}
					for _, operation := range p.Operations {
						for op, operands := range operation {
							expression := []string{}
							for _, operand := range operands {
								switch val := operand.(type) {
								case string:
									if strings.HasPrefix(val, pathTemplatePrefix) {
										val = strings.TrimLeft(val, pathTemplatePrefix)
									} else if !strings.HasPrefix(val, tokenPrefix) && !strings.HasPrefix(val, inputPrefix) {
										val = fmt.Sprintf("x.%v", val)
									} else {
										if op == "membership" {
											val = fmt.Sprintf("%v[_]", val)
										}
									}
									expression = append(expression, val)
								case bool:
									expression = append(expression, strconv.FormatBool(val))
								case int64:
									expression = append(expression, strconv.FormatInt(val, 10))
								case float64:
									expression = append(expression, strconv.FormatInt(int64(val), 10))
								default:
									return "", fmt.Errorf("illegal type for operand: %T", val)
								}
							}
							expressions = append(expressions, strings.Join(expression, opNameToSymbol[op]))
						}
					}
					listFilter := policySchemaListFilter{
						Source:      p.Source,
						Expressions: expressions,
					}

					schema := PolicySchema{
						Path:       convertOASPathToParsedPath(path),
						Method:     strconv.Quote(method),
						ListFilter: &listFilter,
					}
					schemas = append(schemas, schema)
				}
			}

			// check for "x-security-rego-overwrite-filter" extension
			if val, ok := operation.ExtensionProps.Extensions[oasSecExtRegoOverwriteFilter]; ok {
				data, ok := val.(json.RawMessage)
				if !ok {
					return "", fmt.Errorf("OpenAPI extensions: type assertion error")
				}

				var policySchemaOverwriteFilters []policySchemaOverwriteFilter
				err := json.Unmarshal(data, &policySchemaOverwriteFilters)
				if err != nil {
					return "", err
				}

				for i, p := range policySchemaOverwriteFilters {
					ruleExpressions := [][]string{}
					for _, rule := range p.Rules {
						expressions := []string{}
						for _, operation := range rule.Operations {
							for op, operands := range operation {
								expression := []string{}
								for _, operand := range operands {
									switch val := operand.(type) {
									case string:
										if strings.HasPrefix(val, pathTemplatePrefix) {
											val = strings.TrimLeft(val, pathTemplatePrefix)
										} else if !strings.HasPrefix(val, tokenPrefix) && !strings.HasPrefix(val, "\"") {
											val = fmt.Sprintf("input.object.%v", val)
										} else {
											if op == "membership" {
												val = fmt.Sprintf("%v[_]", val)
											}
										}
										expression = append(expression, val)
									case bool:
										expression = append(expression, strconv.FormatBool(val))
									case int64:
										expression = append(expression, strconv.FormatInt(val, 10))
									case float64:
										expression = append(expression, strconv.FormatInt(int64(val), 10))
									default:
										return "", fmt.Errorf("illegal type for operand: %T", val)
									}
								}
								expressions = append(expressions, strings.Join(expression, opNameToSymbol[op]))
							}
						}
						ruleExpressions = append(ruleExpressions, expressions)
					}

					if p.Value == nil {
						p.Value = "null"
					}

					overwriteFilter := policySchemaOverwriteFilter{
						Field:          p.Field,
						Value:          p.Value,
						Negated:        p.Negated,
						HelperRuleName: fmt.Sprintf("%v%v", helperRuleName, i+1),
						Expressions:    ruleExpressions,
					}

					schema := PolicySchema{
						Path:            convertOASPathToParsedPath(path),
						Method:          strconv.Quote(method),
						OverwriteFilter: &overwriteFilter,
					}
					schemas = append(schemas, schema)
				}
			}

			// check for "x-security-rego-boolean-filter" extension
			if val, ok := operation.ExtensionProps.Extensions[oasSecExtRegoBooleanFilter]; ok {
				data, ok := val.(json.RawMessage)
				if !ok {
					return "", fmt.Errorf("OpenAPI extensions: type assertion error")
				}

				var policySchemaBooleanFilters []policySchemaBooleanFilter
				err := json.Unmarshal(data, &policySchemaBooleanFilters)
				if err != nil {
					return "", err
				}

				for _, p := range policySchemaBooleanFilters {
					ruleExpressions := [][]string{}
					for _, rule := range p.Rules {
						expressions := []string{}
						for _, operation := range rule.Operations {
							for op, operands := range operation {
								expression := []string{}
								for _, operand := range operands {
									switch val := operand.(type) {
									case string:
										if strings.HasPrefix(val, pathTemplatePrefix) {
											val = strings.TrimLeft(val, pathTemplatePrefix)
										} else if op == "membership" {
											val = fmt.Sprintf("%v[_]", val)
										} else if op == "negation" {
											val = fmt.Sprintf("not %v", val)
										}
										expression = append(expression, val)
									case bool:
										expression = append(expression, strconv.FormatBool(val))
									case int64:
										expression = append(expression, strconv.FormatInt(val, 10))
									case float64:
										expression = append(expression, strconv.FormatInt(int64(val), 10))
									default:
										return "", fmt.Errorf("illegal type for operand: %T", val)
									}
								}
								expressions = append(expressions, strings.Join(expression, opNameToSymbol[op]))
							}
						}
						ruleExpressions = append(ruleExpressions, expressions)
					}

					booleanFilter := policySchemaBooleanFilter{
						Expressions: ruleExpressions,
					}

					schema := PolicySchema{
						Path:          convertOASPathToParsedPath(path),
						Method:        strconv.Quote(method),
						BooleanFilter: &booleanFilter,
					}
					schemas = append(schemas, schema)
				}
			}

			// generate boolean rules if boolean filter not defined
			if _, ok := operation.ExtensionProps.Extensions[oasSecExtRegoBooleanFilter]; !ok {
				schema := PolicySchema{
					Path:   convertOASPathToParsedPath(path),
					Method: strconv.Quote(method),
				}
				schemas = append(schemas, schema)
			}
		}
	}
	return generateRego(schemas, packageName)
}

func getSecuritySchemes(secReqs *openapi3.SecurityRequirements) map[string][]string {
	securitySchemesMap := make(map[string][]string)
	for _, req := range *secReqs {
		for scheme, scopes := range req {
			securitySchemesMap[scheme] = scopes
		}
	}
	return securitySchemesMap
}

func getFormattedMaskFields(maskFields []string) string {
	result := make([]string, len(maskFields))

	for i := range maskFields {
		result[i] = strconv.Quote(maskFields[i])
	}

	return fmt.Sprintf("[%v]", strings.Join(result, ","))
}

func generateRego(schemas []PolicySchema, packageName string) (string, error) {

	policyTemplate := fmt.Sprintf(regoTemplate, packageName)

	t := template.New("policy_template")
	t, err := t.Parse(policyTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer

	err = t.Execute(&buf, schemas)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// convertOASPathToParsedPath converts OAS URL path with parameters
// to a path represented as a string array where variables are not surrounded
// by double quotes. Valid input parameters are:
//   {param}
//   {param*}
//   {.param}
//   {.param*}
//   {;param}
//   {;param*}
//   {?param}
//   {?param*}
func convertOASPathToParsedPath(path string) string {
	match := pathParamRE.ReplaceAllString(path, ":$1")
	splitPath := strings.Split(strings.TrimLeft(match, "/"), "/")

	// add "["
	result := "["
	for i := 0; i < len(splitPath); i++ {
		// parameter
		if strings.HasPrefix(splitPath[i], ":") {
			result += fmt.Sprintf("%s, ", strings.TrimLeft(splitPath[i], ":"))
		} else {
			result += fmt.Sprintf("\"%s\", ", splitPath[i])
		}
	}

	// add "]"
	result = strings.TrimSuffix(strings.TrimSpace(result), ",") + "]"

	// handle root path
	if result == "[\"\"]" {
		return "[\"/\"]"
	}
	return result
}
