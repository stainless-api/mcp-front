package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stainless-api/mcp-front/internal/testutil"
	"github.com/stretchr/testify/mock"
)

func TestStripInboundHeaders(t *testing.T) {
	mockClient := new(testutil.MockMCPClient)
	mockClient.On("CallTool", mock.Anything, mock.MatchedBy(func(req mcp.CallToolRequest) bool {
		return req.Header == nil && req.Params.Name == "query"
	})).Return(&mcp.CallToolResult{}, nil)

	handler := stripInboundHeaders(mockClient)
	request := mcp.CallToolRequest{}
	request.Params.Name = "query"
	request.Header = http.Header{"Accept-Encoding": []string{"gzip, deflate"}, "Cookie": []string{"session=abc"}}

	if _, err := handler(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	mockClient.AssertExpectations(t)
}
