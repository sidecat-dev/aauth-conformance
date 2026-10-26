package conformance

import (
	"encoding/json"
	"fmt"
	"mime"
	"reflect"
	"strings"

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
		var present bool
		actual, present = body[a.Member]
		if !present {
			result.Detail = "missing JSON member"
			return result
		}
	case "sfv-token", "sfv-strings", "sfv-string-set", "sfv-integer":
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
		if a.Kind == "sfv-integer" {
			item, ok := member.(httpsfv.Item)
			if !ok || item.Params != nil && len(item.Params.Names()) != 0 {
				result.Detail = "member is not a bare Integer item"
				return result
			}
			value, ok := item.Value.(int64)
			if !ok {
				result.Detail = "member is not an Integer"
				return result
			}
			actual = float64(value)
		} else if a.Kind == "sfv-token" {
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
			if a.Kind == "sfv-string-set" {
				want, ok := expected.([]any)
				if !ok {
					result.Detail = "expected value is not a String list"
					return result
				}
				gotSet, wantSet := map[string]bool{}, map[string]bool{}
				for _, v := range values {
					gotSet[v.(string)] = true
				}
				for _, v := range want {
					text, ok := v.(string)
					if !ok {
						result.Detail = "expected item is not a String"
						return result
					}
					wantSet[text] = true
				}
				actual, expected = gotSet, wantSet
			}
		}
	case "sfv-trailer-integer", "sfv-trailer-if-present":
		if a.Kind == "sfv-trailer-if-present" && (r.Trailer == nil || len(r.Trailer.Values(a.Header)) == 0) {
			result.State = "pass"
			result.Actual = nil
			result.Detail = "no trailer"
			return result
		}
		if r.Trailer == nil || len(r.Trailer.Values(a.Header)) == 0 {
			result.Detail = "missing trailer"
			return result
		}
		dictionary, err := httpsfv.UnmarshalDictionary(r.Trailer.Values(a.Header))
		if err != nil {
			result.Detail = err.Error()
			return result
		}
		member, ok := dictionary.Get(a.Member)
		if !ok {
			result.Detail = "missing dictionary member"
			return result
		}
		item, ok := member.(httpsfv.Item)
		if !ok || item.Params != nil && len(item.Params.Names()) != 0 {
			result.Detail = "member is not a bare Integer item"
			return result
		}
		value, ok := item.Value.(int64)
		if !ok {
			result.Detail = "member is not an Integer"
			return result
		}
		actual = float64(value)
	case "sfv-absent", "sfv-trailer-absent":
		values := r.Header.Values(a.Header)
		if a.Kind == "sfv-trailer-absent" {
			values = nil
			if r.Trailer != nil {
				values = r.Trailer.Values(a.Header)
			}
		}
		if len(values) == 0 {
			actual = true
			break
		}
		dictionary, err := httpsfv.UnmarshalDictionary(values)
		if err != nil {
			result.Detail = err.Error()
			return result
		}
		_, present := dictionary.Get(a.Member)
		actual = !present
	case "json-path":
		var body any
		if err := json.Unmarshal(r.Body, &body); err != nil {
			result.Detail = err.Error()
			return result
		}
		cursor := body
		present := true
		for _, part := range strings.Split(a.Member, ".") {
			object, ok := cursor.(map[string]any)
			if !ok {
				present = false
				break
			}
			cursor, present = object[part]
			if !present {
				break
			}
		}
		if !present {
			if expected != nil {
				result.Detail = "missing JSON path"
				return result
			}
			actual = nil
			break
		}
		if expected == nil {
			result.Actual = cursor
			result.Detail = "JSON path is present"
			return result
		}
		actual = cursor
	case "header-equals":
		actual = r.Header.Get(a.Header)
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
