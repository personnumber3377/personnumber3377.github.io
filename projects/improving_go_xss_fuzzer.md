# Improving go xss fuzzer

Ok, so my current code looks something like this here:

```

package fuck

import (
	"bytes"
	"strings"
	"testing"
	// "net/html/template"
	"html/template"
	// "net/html"
	// "html"
	"os"
	"bufio"
	"io/ioutil"
)

func FuzzTemplate(f *testing.F) {
	// Seed corpus
	f.Add([]byte(`<h1>{{.Name}}</h1>`))
	f.Add([]byte(`<a href="{{.UserID}}">test</a>`))
	f.Add([]byte(`<script>{{.Name}}</script>`))
	f.Add([]byte(`<img src=x onerror=alert(1){{.Name}}alert(1)>Testalert(1)`))

	f.Fuzz(func(t *testing.T, data []byte) {
		payload := string(data)

		// Filter out early if no alert attempt
		if !strings.Contains(payload, "alert(1)") {
			return
		}
		/*
		if !isAllowedHTML(payload) {
			return
		}
		*/

		// Set up template with fixed HTML
		tmpl, err := template.New("fuzz").Parse("<a href='/4ebe354b-cb01-45b5-aa3e-aa2fe2f98091'>{{.Name}}</a>")
		if err != nil {
			return
		}

		info := struct {
			Name string
		}{
			Name: payload,
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, info); err != nil {
			return
		}

		result := buf.String()
		_ = ioutil.WriteFile("input.txt", []byte(result), 0644)

		found, _ := checkCharacterInFile("result.txt", byte('1'))
		if found {
			panic("XSS Detected!")
		}
	})
}
/*
func isAllowedHTML(text string) bool {
	tkn := html.NewTokenizer(strings.NewReader(text))
	for {
		tt := tkn.Next()
		switch {
		case tt == html.ErrorToken:
			return true
		case tt == html.StartTagToken:
			t := tkn.Token()
			if t.Data == "h1" {
				continue
			} else {
				return false
			}
		}
	}
}
*/
func checkCharacterInFile(filePath string, targetChar byte) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if contains(scanner.Text(), targetChar) {
			return true, nil
		}
	}
	return false, scanner.Err()
}

func contains(line string, targetChar byte) bool {
	for i := 0; i < len(line); i++ {
		if line[i] == targetChar {
			return true
		}
	}
	return false
}

```

Now the `input.txt` file is actually used by an external python script which then tries loading the data and checks for xss. I am going to take a look at the tests in the golang source code and make a script like so:

```

The source code for this script is inside the blog in projects/xss_fuzzer.go

```

this program generates both the templates and the payloads.










