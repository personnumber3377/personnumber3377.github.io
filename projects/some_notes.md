

## Some of my own notes


https://gitlab.com/gitlab-org/gitaly/-/commit/fc3c93bbdae1be7572077a58e56ec86694ae91bc


We had to modify /home/oof/.asdf/installs/golang/1.22.6/go/src/crypto/internal/bigmod/nat_asm.go .

The original contents were these:

{% raw %}
```
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego && (386 || amd64 || arm || arm64 || ppc64 || ppc64le || riscv64 || s390x)

package bigmod

import "internal/cpu"

// amd64 assembly uses ADCX/ADOX/MULX if ADX is available to run two carry
// chains in the flags in parallel across the whole operation, and aggressively
// unrolls loops. arm64 processes four words at a time.
//
// It's unclear why the assembly for all other architectures, as well as for
// amd64 without ADX, perform better than the compiler output.
// TODO(filippo): file cmd/compile performance issue.

var supportADX = cpu.X86.HasADX && cpu.X86.HasBMI2

//go:noescape
func addMulVVW1024(z, x *uint, y uint) (c uint)

//go:noescape
func addMulVVW1536(z, x *uint, y uint) (c uint)

//go:noescape
func addMulVVW2048(z, x *uint, y uint) (c uint)

```
{% endraw %}

the new contents are these:

{% raw %}
```
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego && (386 || amd64 || arm || arm64 || ppc64 || ppc64le || riscv64 || s390x)

package bigmod

import "internal/cpu"

// amd64 assembly uses ADCX/ADOX/MULX if ADX is available to run two carry
// chains in the flags in parallel across the whole operation, and aggressively
// unrolls loops. arm64 processes four words at a time.
//
// It's unclear why the assembly for all other architectures, as well as for
// amd64 without ADX, perform better than the compiler output.
// TODO(filippo): file cmd/compile performance issue.

var supportADX = cpu.X86.HasADX && cpu.X86.HasBMI2


func addMulVVW1024(z, x *uint, y uint) (c uint)


func addMulVVW1536(z, x *uint, y uint) (c uint)


func addMulVVW2048(z, x *uint, y uint) (c uint)

```
{% endraw %}


The bullshit which we probably want to implement is ReadIndex










{% raw %}
```

//go:build gofuzz

package packfile

import (
	"bufio"
	"bytes"

	"gitlab.com/gitlab-org/gitaly/v16/internal/git"
	"gitlab.com/gitlab-org/gitaly/v16/internal/log"
)

// "gitlab.com/gitlab-org/gitaly/v16/internal/log"

func Fuzz(data []byte) int {
	// reader := bufio.NewReader(bytes.NewReader(data))
	// ParseObjectInfo(git.ObjectHashSHA1, reader, true)

	logger := log.ConfigureCommand()

	fo, err := os.Create("index.idx") // Create the file.
	if err != nil {
		panic(err)
	}
	if _, err := fo.Write(data); err != nil { // Write to the file.
		panic(err)
	}

	//err = binary.Write(f, binary.LittleEndian, data)

	// Try to read the file.

	idx, err := ReadIndex(logger, "index.idx")





	// err = binary.Write(f, binary.LittleEndian, data)

	return 0
}


```
{% endraw %}

