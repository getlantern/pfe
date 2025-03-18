//go:build !linux

package main

func main() {
	panic("pfe only runs on linux")
}
