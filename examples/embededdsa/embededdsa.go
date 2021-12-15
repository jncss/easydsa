package main

import (
	"log"

	"github.com/jncss/easydsa"
)

const privatePEMKey = `
-----BEGIN PRIVATE KEY-----
MIIBwTCCAaYwggEeAoGBAPLjsWtC85/aKRcGANH1Qu9MJuQlowJ+xSwbMXMdzAWR
MCLLvG12I7vlr36u4Zz2MrmkbTbycb/KsTRNv93jwAtLftowiQlAv5RpkUTXtRZ/
kYuVB8G/RErZ4S9fs78/78G9YayyNwseiX5Yf+WdMfF3YJbOlx+zOf4ewosARGMJ
AhUAzMOp6nn4tu/uKAf2Q/3IQ9qm2LsCgYAL3M5ohA8JLuO7j4rqpwA1knebiLCX
fZ/bYaaUma8dfyblV4ZmYk7yJCO3hfdMJbnY/YrPxFXkJ8mYJrYe8HQWRp0i8mHV
utBs57r0/9qT6r6KXeKA+u7f4uEpVATXbB/COV223yO1s9sm9MYS587y51VhElQ6
McEzrwlkhistGwKBgQDT99sGYbI0W5Xl6Yj1UoGBlPT2Y2FiBquyVAvbBxsKX6V1
au9myXu1ylnfhmUAB7dBvUjxqmhCuCivpTeVmmVZ91CXJZJZkScsokHbRrGt2IEc
Pan48Wx2v5uX/AnCQD/LJDZ9SkZxN2bl1UUDhoNUsNkFOqso3j1Gsz40CU42UAIV
ALoEpo7fna9UEvhB4PRqAzKNXX5T
-----END PRIVATE KEY-----
`

const publicPEMKey = `
-----BEGIN PUBLIC KEY-----
MIIBpjCCAR4CgYEA8uOxa0Lzn9opFwYA0fVC70wm5CWjAn7FLBsxcx3MBZEwIsu8
bXYju+Wvfq7hnPYyuaRtNvJxv8qxNE2/3ePAC0t+2jCJCUC/lGmRRNe1Fn+Ri5UH
wb9EStnhL1+zvz/vwb1hrLI3Cx6Jflh/5Z0x8Xdgls6XH7M5/h7CiwBEYwkCFQDM
w6nqefi27+4oB/ZD/chD2qbYuwKBgAvczmiEDwku47uPiuqnADWSd5uIsJd9n9th
ppSZrx1/JuVXhmZiTvIkI7eF90wludj9is/EVeQnyZgmth7wdBZGnSLyYdW60Gzn
uvT/2pPqvopd4oD67t/i4SlUBNdsH8I5XbbfI7Wz2yb0xhLnzvLnVWESVDoxwTOv
CWSGKy0bAoGBANP32wZhsjRbleXpiPVSgYGU9PZjYWIGq7JUC9sHGwpfpXVq72bJ
e7XKWd+GZQAHt0G9SPGqaEK4KK+lN5WaZVn3UJclklmRJyyiQdtGsa3YgRw9qfjx
bHa/m5f8CcJAP8skNn1KRnE3ZuXVRQOGg1Sw2QU6qyjePUazPjQJTjZQ
-----END PUBLIC KEY-----
`

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// Load keys
	privateKey, err := new(easydsa.PrivateKey).UnmarshalPEM(privatePEMKey)
	checkError(err)
	publicKey, err := new(easydsa.PublicKey).UnmarshalPEM(publicPEMKey)
	checkError(err)

	// Sign
	signature, err := privateKey.SignFile(easydsa.SHA1, "/etc/hosts")
	checkError(err)

	// Verify
	result, err := publicKey.VerifyFile(easydsa.SHA1, "/etc/hosts", signature)
	checkError(err)
	log.Println(result)
}
