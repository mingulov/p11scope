// p11scope — non-interposing PKCS#11 observer (eBPF uprobes).
// Status: design phase; see docs/superpowers/specs/.
package main

import (
	"fmt"
	"os"
)

const version = "0.0.0-dev"

func main() {
	fmt.Printf("p11scope %s — design phase, no functionality yet\n", version)
	os.Exit(1)
}
