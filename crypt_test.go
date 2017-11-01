package crypt

import (
	"fmt"
	"testing"
)

func TestCrypt(t *testing.T) {
	//TCrc()
	//TSha256()

	//TAES()

	//TRSA()
	//TSignVerify()

	//TEllipticKeys()
	//TElliptic()
	//TEllipticSignVarify()
}

const passphrase = "let it be a passphrase"

func msg() []string {
	return []string{"Simple message", "Simple message!", "simple message"}
}

func TCrc() {
	for _, m := range msg() {
		crc := Crc32([]byte(m))
		fmt.Printf("0x%X is crc32 of <%s>\n", crc, m)
	}
}

func TSha256() {
	for _, m := range msg() {
		sha256 := PassKey(m)
		fmt.Println(sha256, " is sha256 of ", m)
	}
}

func TAES() {
	key := PassKey(passphrase)
	coder := AES{key[:]}
	fmt.Println("Cryptint with key", coder.Key)

	for _, m := range msg() {
		code, err := coder.Enc([]byte(m))
		if err != nil {
			fmt.Println("Code error: ", err)
		}
		fmt.Println("M: ", []byte(m))
		fmt.Println("C: ", code)
		d, _ := coder.Dec(code)
		fmt.Println("D: ", d, "\n")
	}
}

func TRSA() {

	coder := new(RSA)
	coder.GenKeys()

	for _, m := range msg() {
		fmt.Println("Cryptint ", m, " with RSA")
		code, _ := coder.Enc([]byte(m))

		fmt.Println("M: ", []byte(m))
		fmt.Println("C: ", code)
		d, _ := coder.Dec(code)
		fmt.Println("D: ", d, "\n")
	}
}

func TSignVerify() {
	coder := new(RSA)
	coder.GenKeys()

	ms := msg()

	sign, _ := coder.Sign([]byte(ms[0]))
	fmt.Println("Sign of <", ms[0], ">\n is: ", sign)

	for _, m := range ms {
		check := coder.Verify([]byte(m), sign)
		fmt.Println("Verify <", m, ">: ", check)
	}
}

func TEllipticKeys() {
	coder := new(Elliptic)
	coder.GenKeys()
	priv, _ := coder.Keys()
	fmt.Println(priv)
}

func TElliptic() {
	coder := new(Elliptic)
	coder.GenKeys()

	for _, m := range msg() {
		fmt.Println("Cryptint ", m, " with Elliptic curve")
		code := coder.Enc([]byte(m))

		fmt.Println("M: ", []byte(m))
		fmt.Println("C: ", code)
		d := coder.Dec(code)
		fmt.Println("D: ", d, "\n")
	}
}

func TEllipticSignVarify() {
	coder := new(Elliptic)
	coder.GenKeys()

	ms := msg()

	sign, _ := coder.Sign([]byte(ms[0]))
	fmt.Println("Sign of <", ms[0], ">\n is: ", sign)

	for _, m := range ms {
		check := coder.Verify([]byte(m), sign)
		fmt.Println("Verify <", m, ">: ", check)
	}

}
