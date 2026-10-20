package conformance

import (
	"encoding/json"
	"fmt"
	"mime"
	"reflect"

	"github.com/dunglas/httpsfv"
)

func Check(a Assertion, r Response) Result {
	result := Result{Assertion: a.ID, Clause: a.Clause, Expected: a.Equals, State: "fail"}
	var expected, actual any
	if err := json.Unmarshal(a.Equals, &expected); err != nil {
		result.Detail = err.Error()
		return result
	}
	switch a.Kind {
	case "status":
		actual = float64(r.Status)
	case "json-member":
		var body map[string]any
		if err := json.Unmarshal(r.Body, &body); err != nil {
			result.Detail = err.Error()
			return result
		}
		actual = body[a.Member]
	case "sfv-token", "sfv-strings":
		dictionary, err := httpsfv.UnmarshalDictionary(r.Header.Values(a.Header))
		if err != nil {
			result.Detail = err.Error()
			return result
		}
		member, ok := dictionary.Get(a.Member)
		if !ok {
			result.Detail = "missing dictionary member"
			return result
		}
		if a.Kind == "sfv-token" {
			item, ok := member.(httpsfv.Item)
			if !ok {
				result.Detail = "member is not an Item"
				return result
			}
			token, ok := item.Value.(httpsfv.Token)
			if !ok {
				result.Detail = "member is not a Token"
				return result
			}
			actual = string(token)
		} else {
			list, ok := member.(httpsfv.InnerList)
			if !ok {
				result.Detail = "member is not an Inner List"
				return result
			}
			values := []any{}
			for _, item := range list.Items {
				v, ok := item.Value.(string)
				if !ok {
					result.Detail = "list item is not a String"
					return result
				}
				values = append(values, v)
			}
			actual = values
		}
	case "problem-if-present":
		media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if media != "application/problem+json" {
			result.State = "not_exercised"
			result.Detail = "draft permits other body representations"
			return result
		}
		var body map[string]any
		if err := json.Unmarshal(r.Body, &body); err != nil {
			result.Detail = err.Error()
			return result
		}
		actual = body["type"]
		expected = "urn:ietf:params:sig-error:" + fmt.Sprint(expected)
		if status, ok := body["status"]; ok && status != float64(r.Status) {
			result.Detail = "problem status disagrees with HTTP status"
			return result
		}
	default:
		result.Detail = "unknown assertion kind"
		return result
	}
	result.Actual = actual
	if reflect.DeepEqual(actual, expected) {
		result.State = "pass"
	}
	return result
}
