package gateway

import (
	"fmt"
	"strings"
)

const namespaceSeparator = "__"

func NamespaceTool(serviceName, toolName string) string {
	return serviceName + namespaceSeparator + toolName
}

func ParseNamespacedTool(name string) (serviceName, toolName string, err error) {
	parts := strings.SplitN(name, namespaceSeparator, 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid namespaced tool name: %q", name)
	}
	return parts[0], parts[1], nil
}
