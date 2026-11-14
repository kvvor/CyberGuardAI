package api

import (
	"context"
	"github.com/getkin/kin-openapi/openapi3"
	"testing"
)

func TestOpenAPIContract(t *testing.T) {
	loader := openapi3.NewLoader()
	doc, e := loader.LoadFromFile("../../../docs/openapi.yaml")
	if e != nil {
		t.Fatal(e)
	}
	if e = doc.Validate(context.Background()); e != nil {
		t.Fatal(e)
	}
}
