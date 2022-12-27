// from github.com/!azure/go-autorest/autorest/to@v0.4.0/convert.go
package to

// Copyright 2017 Microsoft Corporation
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

// String returns a string value for the passed string pointer. It returns the empty string if the
// pointer is nil.
func String(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

// Int64Ptr returns a pointer to the passed int64.
func Int64Ptr(i int64) *int64 {
	return &i
}
