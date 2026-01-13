package main

/*
import (
	"fmt"
	"strings"
	"regexp"
)
*/

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {

    tests := []struct {
        name   string
        input  string
        output string
	}{
        {
                "if",
                "{{if .T}}Hello{{end}}, {{.C}}!",
                "Hello, &lt;Cincinnati&gt;!",
        },
        {
                "else",
                "{{if .F}}{{.H}}{{else}}{{.G}}{{end}}!",
                "&lt;Goodbye&gt;!",
        },
        {
                "overescaping1",
                "Hello, {{.C | html}}!",
                "Hello, &lt;Cincinnati&gt;!",
        },
        {
                "overescaping2",
                "Hello, {{html .C}}!",
                "Hello, &lt;Cincinnati&gt;!",
        },
        {
                "overescaping3",
                "{{with .C}}{{$msg := .}}Hello, {{$msg}}!{{end}}",
                "Hello, &lt;Cincinnati&gt;!",
        },
        {
                "assignment",
                "{{if $x := .H}}{{$x}}{{end}}",
                "&lt;Hello&gt;",
        },
        {
                "withBody",
                "{{with .H}}{{.}}{{end}}",
                "&lt;Hello&gt;",
        },
        {
                "withElse",
                "{{with .E}}{{.}}{{else}}{{.H}}{{end}}",
                "&lt;Hello&gt;",
        },
        {
                "rangeBody",
                "{{range .A}}{{.}}{{end}}",
                "&lt;a&gt;&lt;b&gt;",
        },
        {
                "rangeElse",
                "{{range .E}}{{.}}{{else}}{{.H}}{{end}}",
                "&lt;Hello&gt;",
        },
        {
                "nonStringValue",
                "{{.T}}",
                "true",
        },
        {
                "untypedNilValue",
                "{{.U}}",
                "",
        },
        {
                "typedNilValue",
                "{{.Z}}",
                "&lt;nil&gt;",
        },
        {
                "constant",
                `<a href="/search?q={{"'a<b'"}}">`,
                `<a href="/search?q=%27a%3cb%27">`,
        },
        {
                "multipleAttrs",
                "<a b=1 c={{.H}}>",
                "<a b=1 c=&lt;Hello&gt;>",
        },
        {
                "urlStartRel",
                `<a href='{{"/foo/bar?a=b&c=d"}}'>`,
                `<a href='/foo/bar?a=b&amp;c=d'>`,
        },
        {
                "urlStartAbsOk",
                `<a href='{{"http://example.com/foo/bar?a=b&c=d"}}'>`,
                `<a href='http://example.com/foo/bar?a=b&amp;c=d'>`,
        },
        {
                "protocolRelativeURLStart",
                `<a href='{{"//example.com:8000/foo/bar?a=b&c=d"}}'>`,
                `<a href='//example.com:8000/foo/bar?a=b&amp;c=d'>`,
        },
        {
                "pathRelativeURLStart",
                `<a href="{{"/javascript:80/foo/bar"}}">`,
                `<a href="/javascript:80/foo/bar">`,
        },
        {
                "dangerousURLStart",
                `<a href='{{"javascript:alert(%22pwned%22)"}}'>`,
                `<a href='#ZgotmplZ'>`,
        },
        {
                "dangerousURLStart2",
                `<a href='  {{"javascript:alert(%22pwned%22)"}}'>`,
                `<a href='  #ZgotmplZ'>`,
        },
        {
                "nonHierURL",
                `<a href={{"mailto:Muhammed \"The Greatest\" Ali <m.ali@example.com>"}}>`,
                `<a href=mailto:Muhammed%20%22The%20Greatest%22%20Ali%20%3cm.ali@example.com%3e>`,
        },
        {
                "urlPath",
                `<a href='http://{{"javascript:80"}}/foo'>`,
                `<a href='http://javascript:80/foo'>`,
        },
        {
                "urlQuery",
                `<a href='/search?q={{.H}}'>`,
                `<a href='/search?q=%3cHello%3e'>`,
        },
        {
                "urlFragment",
                `<a href='/faq#{{.H}}'>`,
                `<a href='/faq#%3cHello%3e'>`,
        },
        {
                "urlBranch",
                `<a href="{{if .F}}/foo?a=b{{else}}/bar{{end}}">`,
                `<a href="/bar">`,
        },
        {
                "urlBranchConflictMoot",
                `<a href="{{if .T}}/foo?a={{else}}/bar#{{end}}{{.C}}">`,
                `<a href="/foo?a=%3cCincinnati%3e">`,
        },
        {
                "jsStrValue",
                "<button onclick='alert({{.H}})'>",
                `<button onclick='alert(&#34;\u003cHello\u003e&#34;)'>`,
        },
        {
                "jsNumericValue",
                "<button onclick='alert({{.N}})'>",
                `<button onclick='alert( 42 )'>`,
        },
        {
                "jsBoolValue",
                "<button onclick='alert({{.T}})'>",
                `<button onclick='alert( true )'>`,
        },
        {
                "jsNilValueTyped",
                "<button onclick='alert(typeof{{.Z}})'>",
                `<button onclick='alert(typeof null )'>`,
        },
        {
                "jsNilValueUntyped",
                "<button onclick='alert(typeof{{.U}})'>",
                `<button onclick='alert(typeof null )'>`,
        },
        {
                "jsObjValue",
                "<button onclick='alert({{.A}})'>",
                `<button onclick='alert([&#34;\u003ca\u003e&#34;,&#34;\u003cb\u003e&#34;])'>`,
        },
        {
                "jsObjValueScript",
                "<script>alert({{.A}})</script>",
                `<script>alert(["\u003ca\u003e","\u003cb\u003e"])</script>`,
        },
        {
                "jsObjValueNotOverEscaped",
                "<button onclick='alert({{.A | html}})'>",
                `<button onclick='alert([&#34;\u003ca\u003e&#34;,&#34;\u003cb\u003e&#34;])'>`,
        },
        {
                "jsStr",
                "<button onclick='alert(&quot;{{.H}}&quot;)'>",
                `<button onclick='alert(&quot;\u003cHello\u003e&quot;)'>`,
        },
        {
                "badMarshaler",
                `<button onclick='alert(1/{{.B}}in numbers)'>`,
                `<button onclick='alert(1/ /* json: error calling MarshalJSON for type *template.badMarshaler: invalid character &#39;f&#39; looking for beginning of object key string */null in numbers)'>`,
        },
        {
                "jsMarshaler",
                `<button onclick='alert({{.M}})'>`,
                `<button onclick='alert({&#34;\u003cfoo\u003e&#34;:&#34;O&#39;Reilly&#34;})'>`,
        },
        {
                "jsStrNotUnderEscaped",
                "<button onclick='alert({{.C | urlquery}})'>",
                // URL escaped, then quoted for JS.
                `<button onclick='alert(&#34;%3CCincinnati%3E&#34;)'>`,
        },
        {
                "jsRe",
                `<button onclick='alert(/{{"foo+bar"}}/.test(""))'>`,
                `<button onclick='alert(/foo\u002bbar/.test(""))'>`,
        },
        {
                "jsReBlank",
                `<script>alert(/{{""}}/.test(""));</script>`,
                `<script>alert(/(?:)/.test(""));</script>`,
        },
        {
                "jsReAmbigOk",
                `<script>{{if true}}var x = 1{{end}}</script>`,
                // The {if} ends in an ambiguous jsCtx but there is
                // no slash following so we shouldn't care.
                `<script>var x = 1</script>`,
        },
        {
                "styleBidiKeywordPassed",
                `<p style="dir: {{"ltr"}}">`,
                `<p style="dir: ltr">`,
        },
        {
                "styleBidiPropNamePassed",
                `<p style="border-{{"left"}}: 0; border-{{"right"}}: 1in">`,
                `<p style="border-left: 0; border-right: 1in">`,
        },
        {
                "styleExpressionBlocked",
                `<p style="width: {{"expression(alert(1337))"}}">`,
                `<p style="width: ZgotmplZ">`,
        },
        {
                "styleTagSelectorPassed",
                `<style>{{"p"}} { color: pink }</style>`,
                `<style>p { color: pink }</style>`,
        },
        {
                "styleIDPassed",
                `<style>p{{"#my-ID"}} { font: Arial }</style>`,
                `<style>p#my-ID { font: Arial }</style>`,
        },
        {
                "styleClassPassed",
                `<style>p{{".my_class"}} { font: Arial }</style>`,
                `<style>p.my_class { font: Arial }</style>`,
        },
        {
                "styleQuantityPassed",
                `<a style="left: {{"2em"}}; top: {{0}}">`,
                `<a style="left: 2em; top: 0">`,
        },
        {
                "stylePctPassed",
                `<table style=width:{{"100%"}}>`,
                `<table style=width:100%>`,
        },
        {
                "styleColorPassed",
                `<p style="color: {{"#8ff"}}; background: {{"#000"}}">`,
                `<p style="color: #8ff; background: #000">`,
        },
        {
                "styleObfuscatedExpressionBlocked",
                `<p style="width: {{"  e\\78preS\x00Sio/**/n(alert(1337))"}}">`,
                `<p style="width: ZgotmplZ">`,
        },
        {
                "styleMozBindingBlocked",
                `<p style="{{"-moz-binding(alert(1337))"}}: ...">`,
                `<p style="ZgotmplZ: ...">`,
        },
        {
                "styleObfuscatedMozBindingBlocked",
                `<p style="{{"  -mo\\7a-B\x00I/**/nding(alert(1337))"}}: ...">`,
                `<p style="ZgotmplZ: ...">`,
        },
        {
                "styleFontNameString",
                `<p style='font-family: "{{"Times New Roman"}}"'>`,
                `<p style='font-family: "Times New Roman"'>`,
        },
        {
                "styleFontNameString",
                `<p style='font-family: "{{"Times New Roman"}}", "{{"sans-serif"}}"'>`,
                `<p style='font-family: "Times New Roman", "sans-serif"'>`,
        },
        {
                "styleFontNameUnquoted",
                `<p style='font-family: {{"Times New Roman"}}'>`,
                `<p style='font-family: Times New Roman'>`,
        },
        {
                "styleURLQueryEncoded",
                `<p style="background: url(/img?name={{"O'Reilly Animal(1)<2>.png"}})">`,
                `<p style="background: url(/img?name=O%27Reilly%20Animal%281%29%3c2%3e.png)">`,
        },
        {
                "styleQuotedURLQueryEncoded",
                `<p style="background: url('/img?name={{"O'Reilly Animal(1)<2>.png"}}')">`,
                `<p style="background: url('/img?name=O%27Reilly%20Animal%281%29%3c2%3e.png')">`,
        },
        {
                "styleStrQueryEncoded",
                `<p style="background: '/img?name={{"O'Reilly Animal(1)<2>.png"}}'">`,
                `<p style="background: '/img?name=O%27Reilly%20Animal%281%29%3c2%3e.png'">`,
        },
        {
                "styleURLBadProtocolBlocked",
                `<a style="background: url('{{"javascript:alert(1337)"}}')">`,
                `<a style="background: url('#ZgotmplZ')">`,
        },
        {
                "styleStrBadProtocolBlocked",
                `<a style="background: '{{"vbscript:alert(1337)"}}'">`,
                `<a style="background: '#ZgotmplZ'">`,
        },
        {
                "styleStrEncodedProtocolEncoded",
                `<a style="background: '{{"javascript\\3a alert(1337)"}}'">`,
                // The CSS string 'javascript\\3a alert(1337)' does not contain a colon.
                `<a style="background: 'javascript\\3a alert\28 1337\29 '">`,
        },
        {
                "styleURLGoodProtocolPassed",
                `<a style="background: url('{{"http://oreilly.com/O'Reilly Animals(1)<2>;{}.html"}}')">`,
                `<a style="background: url('http://oreilly.com/O%27Reilly%20Animals%281%29%3c2%3e;%7b%7d.html')">`,
        },
        {
                "styleStrGoodProtocolPassed",
                `<a style="background: '{{"http://oreilly.com/O'Reilly Animals(1)<2>;{}.html"}}'">`,
                `<a style="background: 'http\3a\2f\2foreilly.com\2fO\27Reilly Animals\28 1\29\3c 2\3e\3b\7b\7d.html'">`,
        },
        {
                "styleURLEncodedForHTMLInAttr",
                `<a style="background: url('{{"/search?img=foo&size=icon"}}')">`,
                `<a style="background: url('/search?img=foo&amp;size=icon')">`,
        },
        {
                "styleURLNotEncodedForHTMLInCdata",
                `<style>body { background: url('{{"/search?img=foo&size=icon"}}') }</style>`,
                `<style>body { background: url('/search?img=foo&size=icon') }</style>`,
        },
        {
                "styleURLMixedCase",
                `<p style="background: URL(#{{.H}})">`,
                `<p style="background: URL(#%3cHello%3e)">`,
        },
        {
                "stylePropertyPairPassed",
                `<a style='{{"color: red"}}'>`,
                `<a style='color: red'>`,
        },
        {
                "styleStrSpecialsEncoded",
                `<a style="font-family: '{{"/**/'\";:// \\"}}', &quot;{{"/**/'\";:// \\"}}&quot;">`,
                `<a style="font-family: '\2f**\2f\27\22\3b\3a\2f\2f  \\', &quot;\2f**\2f\27\22\3b\3a\2f\2f  \\&quot;">`,
        },
        {
                "styleURLSpecialsEncoded",
                `<a style="border-image: url({{"/**/'\";:// \\"}}), url(&quot;{{"/**/'\";:// \\"}}&quot;), url('{{"/**/'\";:// \\"}}'), 'http://www.example.com/?q={{"/**/'\";:// \\"}}''">`,
                `<a style="border-image: url(/**/%27%22;://%20%5c), url(&quot;/**/%27%22;://%20%5c&quot;), url('/**/%27%22;://%20%5c'), 'http://www.example.com/?q=%2f%2a%2a%2f%27%22%3b%3a%2f%2f%20%5c''">`,
        },
        {
                "HTML comment",
                "<b>Hello, <!-- name of world -->{{.C}}</b>",
                "<b>Hello, &lt;Cincinnati&gt;</b>",
        },
        {
                "HTML comment not first < in text node.",
                "<<!-- -->!--",
                "&lt;!--",
        },
        {
                "HTML normalization 1",
                "a < b",
                "a &lt; b",
        },
        {
                "HTML normalization 2",
                "a << b",
                "a &lt;&lt; b",
        },
        {
                "HTML normalization 3",
                "a<<!-- --><!-- -->b",
                "a&lt;b",
        },
        {
                "HTML doctype not normalized",
                "<!DOCTYPE html>Hello, World!",
                "<!DOCTYPE html>Hello, World!",
        },
        {
                "HTML doctype not case-insensitive",
                "<!doCtYPE htMl>Hello, World!",
                "<!doCtYPE htMl>Hello, World!",
        },
        {
                "No doctype injection",
                `<!{{"DOCTYPE"}}`,
                "&lt;!DOCTYPE",
        },
        {
                "Split HTML comment",
                "<b>Hello, <!-- name of {{if .T}}city -->{{.C}}{{else}}world -->{{.W}}{{end}}</b>",
                "<b>Hello, &lt;Cincinnati&gt;</b>",
        },
        {
                "JS line comment",
                "<script>for (;;) { if (c()) break// foo not a label\n" +
                        "foo({{.T}});}</script>",
                "<script>for (;;) { if (c()) break\n" +
                        "foo( true );}</script>",
        },
        {
                "JS multiline block comment",
                "<script>for (;;) { if (c()) break/* foo not a label\n" +
                        " */foo({{.T}});}</script>",
                // Newline separates break from call. If newline
                // removed, then break will consume label leaving
                // code invalid.
                "<script>for (;;) { if (c()) break\n" +
                        "foo( true );}</script>",
        },
        {
                "JS single-line block comment",
                "<script>for (;;) {\n" +
                        "if (c()) break/* foo a label */foo;" +
                        "x({{.T}});}</script>",
                // Newline separates break from call. If newline
                // removed, then break will consume label leaving
                // code invalid.
                "<script>for (;;) {\n" +
                        "if (c()) break foo;" +
                        "x( true );}</script>",
        },
        {
                "JS block comment flush with mathematical division",
                "<script>var a/*b*//c\nd</script>",
                "<script>var a /c\nd</script>",
        },
        {
                "JS mixed comments",
                "<script>var a/*b*///c\nd</script>",
                "<script>var a \nd</script>",
        },
        {
                "CSS comments",
                "<style>p// paragraph\n" +
                        `{border: 1px/* color */{{"#00f"}}}</style>`,
                "<style>p\n" +
                        "{border: 1px #00f}</style>",
        },
        {
                "JS attr block comment",
                `<a onclick="f(&quot;&quot;); /* alert({{.H}}) */">`,
                // Attribute comment tests should pass if the comments
                // are successfully elided.
                `<a onclick="f(&quot;&quot;); /* alert() */">`,
        },
        {
                "JS attr line comment",
                `<a onclick="// alert({{.G}})">`,
                `<a onclick="// alert()">`,
        },
        {
                "CSS attr block comment",
                `<a style="/* color: {{.H}} */">`,
                `<a style="/* color:  */">`,
        },
        {
                "CSS attr line comment",
                `<a style="// color: {{.G}}">`,
                `<a style="// color: ">`,
        },
        {
                "HTML substitution commented out",
                "<p><!-- {{.H}} --></p>",
                "<p></p>",
        },
        {
                "Comment ends flush with start",
                "<!--{{.}}--><script>/*{{.}}*///{{.}}\n</script><style>/*{{.}}*///{{.}}\n</style><a onclick='/*{{.}}*///{{.}}' style='/*{{.}}*///{{.}}'>",
                "<script> \n</script><style> \n</style><a onclick='/**///' style='/**///'>",
        },
        {
                "typed HTML in text",
                `{{.W}}`,
                `&iexcl;<b class="foo">Hello</b>, <textarea>O'World</textarea>!`,
        },
        {
                "typed HTML in attribute",
                `<div title="{{.W}}">`,
                `<div title="&iexcl;Hello, O&#39;World!">`,
        },
        {
                "typed HTML in script",
                `<button onclick="alert({{.W}})">`,
                `<button onclick="alert(&#34;\u0026iexcl;\u003cb class=\&#34;foo\&#34;\u003eHello\u003c/b\u003e, \u003ctextarea\u003eO&#39;World\u003c/textarea\u003e!&#34;)">`,
        },
        {
                "typed HTML in RCDATA",
                `<textarea>{{.W}}</textarea>`,
                `<textarea>&iexcl;&lt;b class=&#34;foo&#34;&gt;Hello&lt;/b&gt;, &lt;textarea&gt;O&#39;World&lt;/textarea&gt;!</textarea>`,
        },
        {
                "range in textarea",
                "<textarea>{{range .A}}{{.}}{{end}}</textarea>",
                "<textarea>&lt;a&gt;&lt;b&gt;</textarea>",
        },
        {
                "No tag injection",
                `{{"10$"}}<{{"script src,evil.org/pwnd.js"}}...`,
                `10$&lt;script src,evil.org/pwnd.js...`,
        },
        {
                "No comment injection",
                `<{{"!--"}}`,
                `&lt;!--`,
        },
        {
                "No RCDATA end tag injection",
                `<textarea><{{"/textarea "}}...</textarea>`,
                `<textarea>&lt;/textarea ...</textarea>`,
        },
        {
                "optional attrs",
                `<img class="{{"iconClass"}}"` +
                        `{{if .T}} id="{{"<iconId>"}}"{{end}}` +
                        // Double quotes inside if/else.
                        ` src=` +
                        `{{if .T}}"?{{"<iconPath>"}}"` +
                        `{{else}}"images/cleardot.gif"{{end}}` +
                        // Missing space before title, but it is not a
                        // part of the src attribute.
                        `{{if .T}}title="{{"<title>"}}"{{end}}` +
                        // Quotes outside if/else.
                        ` alt="` +
                        `{{if .T}}{{"<alt>"}}` +
                        `{{else}}{{if .F}}{{"<title>"}}{{end}}` +
                        `{{end}}"` +
                        `>`,
                `<img class="iconClass" id="&lt;iconId&gt;" src="?%3ciconPath%3e"title="&lt;title&gt;" alt="&lt;alt&gt;">`,
        },
        {
                "conditional valueless attr name",
                `<input{{if .T}} checked{{end}} name=n>`,
                `<input checked name=n>`,
        },
        {
                "conditional dynamic valueless attr name 1",
                `<input{{if .T}} {{"checked"}}{{end}} name=n>`,
                `<input checked name=n>`,
        },
        {
                "conditional dynamic valueless attr name 2",
                `<input {{if .T}}{{"checked"}} {{end}}name=n>`,
                `<input checked name=n>`,
        },
        {
                "dynamic attribute name",
                `<img on{{"load"}}="alert({{"loaded"}})">`,
                // Treated as JS since quotes are inserted.
                `<img onload="alert(&#34;loaded&#34;)">`,
        },
        {
                "bad dynamic attribute name 1",
                // Allow checked, selected, disabled, but not JS or
                // CSS attributes.
                `<input {{"onchange"}}="{{"doEvil()"}}">`,
                `<input ZgotmplZ="doEvil()">`,
        },
        {
                "bad dynamic attribute name 2",
                `<div {{"sTyle"}}="{{"color: expression(alert(1337))"}}">`,
                `<div ZgotmplZ="color: expression(alert(1337))">`,
        },
        {
                "bad dynamic attribute name 3",
                // Allow title or alt, but not a URL.
                `<img {{"src"}}="{{"javascript:doEvil()"}}">`,
                `<img ZgotmplZ="javascript:doEvil()">`,
        },
        {
                "bad dynamic attribute name 4",
                // Structure preservation requires values to associate
                // with a consistent attribute.
                `<input checked {{""}}="Whose value am I?">`,
                `<input checked ZgotmplZ="Whose value am I?">`,
        },
        {
                "dynamic element name",
                `<h{{3}}><table><t{{"head"}}>...</h{{3}}>`,
                `<h3><table><thead>...</h3>`,
        },
        {
                "bad dynamic element name",
                // Dynamic element names are typically used to switch
                // between (thead, tfoot, tbody), (ul, ol), (th, td),
                // and other replaceable sets.
                // We do not currently easily support (ul, ol).
                // If we do change to support that, this test should
                // catch failures to filter out special tag names which
                // would violate the structure preservation property --
                // if any special tag name could be substituted, then
                // the content could be raw text/RCDATA for some inputs
                // and regular HTML content for others.
                `<{{"script"}}>{{"doEvil()"}}</{{"script"}}>`,
                `&lt;script>doEvil()&lt;/script>`,
        },
        {
                "srcset bad URL in second position",
                `<img srcset="{{"/not-an-image#,javascript:alert(1)"}}">`,
                // The second URL is also filtered.
                `<img srcset="/not-an-image#,#ZgotmplZ">`,
        },
        {
                "srcset buffer growth",
                `<img srcset={{",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"}}>`,
                `<img srcset=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,>`,
        },
        {
                "unquoted empty attribute value (plaintext)",
                "<p name={{.U}}>",
                "<p name=ZgotmplZ>",
        },
        {
                "unquoted empty attribute value (url)",
                "<p href={{.U}}>",
                "<p href=ZgotmplZ>",
        },
        {
                "quoted empty attribute value",
                "<p name=\"{{.U}}\">",
                "<p name=\"\">",
        },
	}

	/*
			F: false,
		T: true,
		C: "<Cincinnati>",
		G: "<Goodbye>",
		H: "<Hello>",
		A: []string{"<a>", "<b>"},
		E: []string{},
		N: 42,
		B: &badMarshaler{},
		M: &goodMarshaler{},
		U: nil,
		Z: nil,
		W: HTML(`&iexcl;<b class="foo">Hello</b>, <textarea>O'World</textarea>!`),
	*/

	var the_strings = []string{".F", ".T", ".C", ".G", ".H", ".A", ".E", ".N", ".B", ".M", ".U", ".Z", ".W"} // Just the strings here...

	re := regexp.MustCompile(`{{\s*(.*?)\s*}}`)

	for _, t := range tests {
		// fmt.Println(t.name)
		if !strings.Contains(t.name, "js") && !strings.Contains(t.name, "JS") {
			// If there is no javascript, then let's try to do the stuff here maybe?
			new_string := t.input // strings.Replace(t.input, )
			for i := 0; i < len(the_strings); i++ {
				new_string = strings.Replace(new_string, the_strings[i], ".FUZZ", 1000) // Just replace the shit...
			}

			// fmt.Println(new_string)

			new_string = re.ReplaceAllStringFunc(new_string, func(match string) string {
				// Extract inner contents
				submatch := re.FindStringSubmatch(match)
				if len(submatch) < 2 {
					return match // sanity check, shouldn't happen
				}
				inner := submatch[1]
				if strings.Contains(inner, "script") {
					err := savePayload(inner)
					if err != nil {
						fmt.Println("Failed to save payload:", err)
					}
					return "{{.FUZZ}}"
				}
				return match
			})

			new_string = "`"+new_string+"`,"
			if strings.Contains(new_string, ".FUZZ") {
				fmt.Println(new_string)
			}

			// fmt.Println(new_string)
		}
	}
	//fmt.Println("Hello world!!!");
}

// Generates a random filename
func randomFilename() string {
	bytes := make([]byte, 8)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

// Saves the payload to the "corp" directory
func savePayload(payload string) error {
	dir := "corp"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	filename := filepath.Join(dir, randomFilename() + ".txt")
	return os.WriteFile(filename, []byte(payload), 0644)
}
