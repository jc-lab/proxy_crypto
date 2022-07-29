package engine

import "go.bryk.io/miracl/core"

type KeyPair struct {
	S []byte // private
	W []byte // public
}

type CurveEngine interface {
	GetBGS() int
	GetBFS() int
	GetG1S() int
	GetG2S() int
	GetSecretKeySize() int
	GetPublicKeySize() int
	KeyPairGenerateIKM(IKM []byte) (*KeyPair, error)
	KeyPairGenerate(rng *core.RAND) (*KeyPair, error)
	GeneratePublicKey(S []byte) ([]byte, error)

	Sign(M []byte, S []byte) ([]byte, error)
	Verify(SIG []byte, M []byte, W []byte) int

	PrsDesignatedKey(S []byte, W []byte) ([]byte, error)
	PrsResigningKey(S []byte, W []byte) ([]byte, error)
	PrsResign(inSig []byte, S []byte) ([]byte, error)
}
