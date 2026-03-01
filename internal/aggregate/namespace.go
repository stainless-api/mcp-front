package aggregate

import "strings"

func PrefixToolName(serverName, toolName string) string {
	return serverName + "." + toolName
}

func ParseToolName(namespacedName string) (serverName, toolName string, ok bool) {
	idx := strings.IndexByte(namespacedName, '.')
	if idx < 0 {
		return "", "", false
	}
	return namespacedName[:idx], namespacedName[idx+1:], true
}
