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
	pathParamRE = regexp.MustCompile("{[.;?]?([^{}*]+)\\*?}")
)

const oasExtensionKey = "x-filter"

var regoTemplate = `package %s
default allow = false

token = {"payload": payload} { io.jwt.decode(input.token, [_, payload, _]) }{{range .}}
{{ if .MaskFields }}
filter = {{.MaskFields}} {
  input.path = {{.Path}}
  input.method = {{.Method}}
  {{- with .Scopes}}
  {{- range .}}
  token.payload.claims["{{.}}"]
  {{- end}}
  {{- end}}
}{{else}}
allow = true {
  input.path = {{.Path}}
  input.method = {{.Method}}
  {{- with .Scopes}}
  {{- range .}}
  token.payload.claims["{{.}}"]
  {{- end}}
  {{- end}}
}{{ end }}{{end}}`

// PolicySchema defines the policy to generate
type PolicySchema struct {
	Path       string
	Method     string
	Scopes     []string
	MaskFields string
}

type extensionDefinition map[string][]string

// Generate generates the Rego policy given a OpenAPI 3 spec
func Generate(swagger *openapi3.Swagger, packageName string) (string, error) {

	schemas := []PolicySchema{}

	for path, item := range swagger.Paths {
		for method, operation := range item.Operations() {

			// check for "x-filter" extension
			if operation.ExtensionProps.Extensions[oasExtensionKey] != nil {

				// security requirement object needs to exist as the "x-filter"
				// extension references it
				if operation.Security == nil {
					return "", fmt.Errorf("OpenAPI spec does not specify a Security Requirement Object")
				}

				securitySchemes := getSecuritySchemes(operation.Security)

				data, ok := operation.ExtensionProps.Extensions[oasExtensionKey].(json.RawMessage)
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
							Path:       convertOASPathToParsedPath(path),
							Method:     strconv.Quote(method),
							Scopes:     scopes,
							MaskFields: getFormattedMaskFields(maskFields),
						}
						schemas = append(schemas, schema)
					}
				}

			} else {
				if operation.Security != nil {
					securitySchemes := getSecuritySchemes(operation.Security)
					for _, scopes := range securitySchemes {
						schema := PolicySchema{
							Path:   convertOASPathToParsedPath(path),
							Method: strconv.Quote(method),
							Scopes: scopes,
						}
						schemas = append(schemas, schema)
					}
				} else {
					schema := PolicySchema{
						Path:   convertOASPathToParsedPath(path),
						Method: strconv.Quote(method),
					}
					schemas = append(schemas, schema)
				}
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
