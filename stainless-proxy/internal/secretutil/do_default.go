//go:build !goexperiment.runtimesecret

package secretutil

func Do(f func()) { f() }
