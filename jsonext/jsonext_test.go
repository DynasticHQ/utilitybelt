package jsonext

import (
	"fmt"
	"testing"
)

func TestPrettyJson(t *testing.T) {
	type multi [][]byte
	testBytes := multi{
		[]byte(`{"hello": "world"}`),
		[]byte(`{"GoodBye": {"name": "Ninjas", "name": "Samurais"}}`),
		[]byte(`"Foo"="Bar"`),
	}
	expectedOutput := []string{
		`{
  "hello": "world"
}`,
		`{
  "GoodBye": {
    "name": "Ninjas",
    "name": "Samurais"
  }
}`, `"Foo"="Bar"`,
	}
	for i, val := range testBytes {
		transformed, err := PrettyJson(val)
		switch {
		case err != nil && i != 2:
			t.Error(err)
		case string(transformed) != expectedOutput[i] && i != 2:
			t.Error("Outputs do not match")
		case i == 2 && err == nil:
			t.Error("err is suppose to be nil and not ", err)
		case err == nil:
			fmt.Printf("Output:\n%s\nExpected Output\n%s\n\n", transformed, expectedOutput[i])

		}
	}
}
