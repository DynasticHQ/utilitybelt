package jsonext

import "testing"

func TestPrettyJson(t *testing.T) {
	type multi [][]byte
	testBytes := multi{
		[]byte(`{"hello": "world"}`),
		[]byte(`{"GoodBye": {"name": "Ninjas", "name": "Samurais"}}`),
	}
	for _, val := range testBytes {
		transformed, err := PrettyJson(val)
		if err != nil {
			t.Error(err)
		}
	}
}
