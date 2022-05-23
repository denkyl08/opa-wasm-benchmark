package opa_wasm_benchmark_test

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"strconv"
	"testing"
	"text/template"
	"time"

	"github.com/open-policy-agent/opa/ast"
	_ "github.com/open-policy-agent/opa/features/wasm"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/util"
)

func getParsedInput(input map[string]interface{}) (ast.Value, error) {
	var err error
	var parsedInput ast.Value
	var inputInterface map[string]interface{} = input
	rawPtr := util.Reference(inputInterface)
	parsedInput, err = ast.InterfaceToValue(*rawPtr)
	if err != nil {
		return nil, err
	}
	return parsedInput, nil
}

func generatePolicyWithRuleCount(size int) string {
	iRange := []int{}

	for i := 0; i < size; i++ {
		iRange = append(iRange, i)
	}
	var fns = template.FuncMap{
		"last": func(x int, a interface{}) bool {
			return x == reflect.ValueOf(a).Len()-1
		},
	}
	const tmpl = `
package  example

Authorize = result {
	# Match any of the Rules
	result := MatchAnyRule
}

MatchAnyRule() {{range $i, $val := .}}= {"action" : "allow", "rule" : "{{$val}}" } {

MatchListToExactFn1 := {
"exact" : {"api-group-name-{{$val}}-1"}
}
MatchListToExactFn1["exact"][input["API_GROUP"][_]]

input["CLIENT"]["ROLE"] == "client-role-name-{{$val}}"

} {{if not (last $i $)}}else {{end}}{{end}}
`
	t := template.Must(template.New("tmpl").Funcs(fns).Parse(tmpl))
	buf := bytes.NewBuffer(nil)
	err := t.Execute(buf, iRange)
	if err != nil {
		panic(err)
	}
	return buf.String()
}

func parseRegoExpression(expressions []*rego.ExpressionValue) (string, string) {
	ruleUID := ""
	policyResult := "continue"

	if len(expressions) != 1 {
		return policyResult, ruleUID
	}

	mapResults := expressions[0].Value.(map[string]interface{})
	if action, ok := mapResults["action"]; ok {
		policyResult = action.(string)
	}
	if ruleVal, ok := mapResults["rule"]; ok {
		ruleUID = ruleVal.(string)
	}

	return policyResult, ruleUID
}

func prepareQueryWithTarget(target, policy string) (rego.PreparedEvalQuery, error) {
	ctx := context.Background()

	opts := []func(*rego.Rego){
		rego.Query("data.example.Authorize"),
		rego.Package("example"),
		rego.Module("authz.rego", policy),
		rego.Target(target),
	}
	q, err := rego.New(opts...).PrepareForEval(ctx)

	if err != nil {
		return q, err
	}
	return q, nil
}

func BenchmarkWASMComparison(b *testing.B) {
	ctx := context.Background()

	type testCase struct {
		name            string
		policy          string
		roleIndexRanges [2]int
	}

	cases := []testCase{
		{
			name:            "5 indexable roles",
			policy:          generatePolicyWithRuleCount(5),
			roleIndexRanges: [2]int{0, 4},
		},
		{
			name:            "50 indexable roles",
			policy:          generatePolicyWithRuleCount(50),
			roleIndexRanges: [2]int{0, 49},
		},
		{
			name:            "100 indexable roles",
			policy:          generatePolicyWithRuleCount(100),
			roleIndexRanges: [2]int{0, 99},
		},
		{
			name:            "200 indexable roles",
			policy:          generatePolicyWithRuleCount(200),
			roleIndexRanges: [2]int{0, 199},
		},
	}

	rand.Seed(time.Now().UnixNano())

	for _, c := range cases {
		for _, target := range []string{"rego", "wasm"} {
			for _, indexingEnabled := range []bool{true, false} {

				// rule indexing is not supported in wasm target mode
				if indexingEnabled && target == "wasm" {
					continue
				}

				b.Run(fmt.Sprintf("eval_%s_target_%s_indexing_%t", c.name, target, indexingEnabled), func(b *testing.B) {
					q, err := prepareQueryWithTarget(target, c.policy)
					if err != nil {
						b.Fatal(err)
					}
					b.ResetTimer()
					for i := 0; i < b.N; i++ {

						ind := strconv.Itoa(rand.Intn(c.roleIndexRanges[1]-c.roleIndexRanges[0]+1) + c.roleIndexRanges[0])

						inp := map[string]interface{}{
							"CLIENT": map[string]interface{}{
								"ROLE": "client-role-name-" + ind,
							},
							"API_GROUP": []interface{}{"api-group-name-" + ind + "-1"},
						}
						parsedInput, err := getParsedInput(inp)
						if err != nil {
							b.Fatal(err)
						}

						resultSet, err := q.Eval(ctx,
							rego.EvalParsedInput(parsedInput),
							rego.EvalRuleIndexing(indexingEnabled),
						)

						if err != nil {
							b.Fatal(err)
						}

						if len(resultSet) == 0 {
							b.Fatalf("no results for input: %v", inp)
						}

						action, _ := parseRegoExpression(resultSet[0].Expressions)
						if action != "allow" {
							b.Fatal("resulting action is unexpected")
						}
					}
				})
			}
		}
	}
}
