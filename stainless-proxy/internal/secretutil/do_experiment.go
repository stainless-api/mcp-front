//go:build goexperiment.runtimesecret

package secretutil

import "runtime/secret"

func Do(f func()) { secret.Do(f) }
