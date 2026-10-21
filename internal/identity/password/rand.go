package password

import "crypto/rand"

func cryptoRandRead(b []byte) (int, error) { return rand.Read(b) }
