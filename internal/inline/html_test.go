package inline

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractText_IDSelector(t *testing.T) {
	html := `<html><body>
		<nav>Navigation</nav>
		<main id="main-content">
			<h1>Article Title</h1>
			<p>First paragraph of the article.</p>
			<p>Second paragraph with <strong>bold</strong> text.</p>
		</main>
		<footer>Footer stuff</footer>
	</body></html>`

	text, err := ExtractText(strings.NewReader(html), "#main-content")
	require.NoError(t, err)

	assert.Contains(t, text, "Article Title")
	assert.Contains(t, text, "First paragraph of the article.")
	assert.Contains(t, text, "bold")
	assert.NotContains(t, text, "Navigation")
	assert.NotContains(t, text, "Footer stuff")
}

func TestExtractText_ClassSelector(t *testing.T) {
	html := `<html><body>
		<div class="sidebar">Sidebar</div>
		<div class="article-body">
			<p>Article content here.</p>
		</div>
	</body></html>`

	text, err := ExtractText(strings.NewReader(html), ".article-body")
	require.NoError(t, err)

	assert.Contains(t, text, "Article content here.")
	assert.NotContains(t, text, "Sidebar")
}

func TestExtractText_TagSelector(t *testing.T) {
	html := `<html><body>
		<nav>Nav</nav>
		<article><p>Article text.</p></article>
	</body></html>`

	text, err := ExtractText(strings.NewReader(html), "article")
	require.NoError(t, err)

	assert.Contains(t, text, "Article text.")
	assert.NotContains(t, text, "Nav")
}

func TestExtractText_FallbackToBody(t *testing.T) {
	html := `<html><body><p>Body content only.</p></body></html>`

	text, err := ExtractText(strings.NewReader(html), "#nonexistent")
	require.NoError(t, err)
	assert.Contains(t, text, "Body content only.")
}

func TestExtractText_StripsScriptAndStyle(t *testing.T) {
	html := `<html><body>
		<div id="content">
			<script>var x = 1;</script>
			<style>.foo { color: red; }</style>
			<p>Visible text.</p>
		</div>
	</body></html>`

	text, err := ExtractText(strings.NewReader(html), "#content")
	require.NoError(t, err)

	assert.Contains(t, text, "Visible text.")
	assert.NotContains(t, text, "var x")
	assert.NotContains(t, text, "color: red")
}

func TestExtractText_PreservesBlockStructure(t *testing.T) {
	html := `<html><body>
		<div id="content">
			<h2>Section One</h2>
			<p>Paragraph one.</p>
			<h2>Section Two</h2>
			<p>Paragraph two.</p>
		</div>
	</body></html>`

	text, err := ExtractText(strings.NewReader(html), "#content")
	require.NoError(t, err)

	assert.Contains(t, text, "Section One")
	assert.Contains(t, text, "Section Two")
	lines := strings.Split(text, "\n\n")
	assert.GreaterOrEqual(t, len(lines), 2)
}

func TestExtractText_EmptySelector(t *testing.T) {
	html := `<html><body><p>Hello</p></body></html>`

	text, err := ExtractText(strings.NewReader(html), "")
	require.NoError(t, err)
	assert.Contains(t, text, "Hello")
}

func TestExtractText_ListItems(t *testing.T) {
	html := `<html><body>
		<div id="content">
			<ul>
				<li>First item</li>
				<li>Second item</li>
			</ul>
		</div>
	</body></html>`

	text, err := ExtractText(strings.NewReader(html), "#content")
	require.NoError(t, err)

	assert.Contains(t, text, "First item")
	assert.Contains(t, text, "Second item")
}
