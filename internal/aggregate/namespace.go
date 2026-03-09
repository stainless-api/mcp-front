package aggregate

import "strings"

func PrefixToolName(serverName, toolName, delimiter string) string {
	return serverName + delimiter + toolName
}

func ParseToolName(namespacedName, delimiter string) (serverName, toolName string, ok bool) {
	idx := strings.Index(namespacedName, delimiter)
	if idx < 0 {
		return "", "", false
	}
	return namespacedName[:idx], namespacedName[idx+len(delimiter):], true
}
