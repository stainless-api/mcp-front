package inline

import (
	"io"
	"strings"

	"golang.org/x/net/html"
)

func ExtractText(r io.Reader, selector string) (string, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return "", err
	}

	target := findElement(doc, selector)
	if target == nil {
		target = findElement(doc, "body")
	}
	if target == nil {
		target = doc
	}

	var b strings.Builder
	extractTextFromNode(&b, target)
	return strings.TrimSpace(b.String()), nil
}

func findElement(n *html.Node, selector string) *html.Node {
	if selector == "" {
		return nil
	}

	match := func(n *html.Node) bool {
		if n.Type != html.ElementNode {
			return false
		}
		switch {
		case strings.HasPrefix(selector, "#"):
			return getAttr(n, "id") == selector[1:]
		case strings.HasPrefix(selector, "."):
			for _, cls := range strings.Fields(getAttr(n, "class")) {
				if cls == selector[1:] {
					return true
				}
			}
			return false
		default:
			return n.Data == selector
		}
	}

	var walk func(*html.Node) *html.Node
	walk = func(n *html.Node) *html.Node {
		if match(n) {
			return n
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if found := walk(c); found != nil {
				return found
			}
		}
		return nil
	}
	return walk(n)
}

func getAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func extractTextFromNode(b *strings.Builder, n *html.Node) {
	if n.Type == html.TextNode {
		text := strings.TrimSpace(n.Data)
		if text != "" {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(text)
		}
		return
	}

	if n.Type == html.ElementNode {
		switch n.Data {
		case "script", "style", "nav", "footer", "header":
			return
		}
	}

	isBlock := false
	if n.Type == html.ElementNode {
		switch n.Data {
		case "p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "br", "tr", "blockquote", "section", "article":
			isBlock = true
		}
	}

	if isBlock && b.Len() > 0 {
		b.WriteString("\n\n")
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		extractTextFromNode(b, c)
	}
}
