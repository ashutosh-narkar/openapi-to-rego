package opa

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/getkin/kin-openapi/openapi3"
)

var (
	pathParamRE = regexp.MustCompile("{[.;?]?([^{}*]+)\\*?}")
)

var regoTemplate = `package %s
default allow = false

token = {"payload": payload} { io.jwt.decode(input.token, [_, payload, _]) }
{{range .}}
allow = true {
  input.path = {{.Path}}
  input.method = {{.Method}}
  {{- with .Scopes}}
  {{- range .}}
  token.payload.claims["{{.}}"]
  {{- end}}
  {{- end}}	
}
{{end}}`

// PolicySchema defines the policy to generate
type PolicySchema struct {
	Path   string
	Method string
	Scopes []string
}

// Generate generates the Rego policy given a OpenAPI 3 spec
func Generate(swagger *openapi3.Swagger, packageName string) (string, error) {

	schemas := []PolicySchema{}

	for path, item := range swagger.Paths {
		for method, operation := range item.Operations() {
			if operation.Security != nil {
				for _, req := range *operation.Security {
					for _, scopes := range req {
						schema := PolicySchema{
							Path:   convertOASPathToParsedPath(path),
							Method: fmt.Sprintf("\"%s\"", method),
							Scopes: scopes,
						}
						schemas = append(schemas, schema)
					}
				}
			} else {
				schema := PolicySchema{
					Path:   convertOASPathToParsedPath(path),
					Method: fmt.Sprintf("\"%s\"", method),
				}
				schemas = append(schemas, schema)
			}
		}
	}

	return generateRego(schemas, packageName)
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
