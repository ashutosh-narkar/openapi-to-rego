package main

import (
	"io/ioutil"
	"os"
	"path"

	"github.com/openapi-to-rego/pkg/opa"
	"github.com/openapi-to-rego/pkg/util"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Config represents the start-up config
type Config struct {
	PolicyPackageName string
	OutputFileName    string
}

var (
	config Config
	cmd    *cobra.Command
)

const (
	defaultPolicyPackageName = "httpapi.authz"
	defaultOutputFileName    = "policy.rego"
)

func init() {
	cmd = &cobra.Command{
		Use:   path.Base(os.Args[0]) + " <OpenAPI spec file> ",
		Short: "OpenAPI to Rego Converter",
		Run:   run,
	}

	cmd.Flags().StringVarP(&config.PolicyPackageName, "package-name", "p", defaultPolicyPackageName, "Rego policy package name")
	cmd.Flags().StringVarP(&config.OutputFileName, "output-filename", "o", defaultOutputFileName, "File to output generated Rego code")
}

func main() {
	cmd.Execute()
}

func run(cmd *cobra.Command, args []string) {

	if len(os.Args) < 2 {
		logrus.Fatal("Specify a path to a OpenAPI 3.0 spec file")
	}

	// load OpenAPI spec
	swagger, err := util.LoadSwagger(os.Args[1])
	if err != nil {
		logrus.WithField("err", err).Fatal("Error loading OpenAPI spec")
	}

	// generate Rego
	rego, err := opa.Generate(swagger, config.PolicyPackageName)
	if err != nil {
		logrus.WithField("err", err).Fatal("Error generating Rego")
	}

	err = ioutil.WriteFile(config.OutputFileName, []byte(rego), 0644)
	if err != nil {
		logrus.WithField("err", err).Fatal("Error writing Rego to file")
	}
}
