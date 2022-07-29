package engine

import (
	"errors"
	"fmt"
	"github.com/jc-lab/miracl_wrapper"
	"go.bryk.io/miracl/core"
)

type CurveEngineImpl struct {
	BGS     int
	BFS     int
	G1S     int
	G2S     int
	reflect miracl_wrapper.CurveReflect
}

func NewCurveEngine(reflect miracl_wrapper.CurveReflect) CurveEngine {
	return &CurveEngineImpl{
		BGS:     reflect.GetBGS(),
		BFS:     reflect.GetBFS(),
		G1S:     reflect.GetG1S(),
		G2S:     reflect.GetG2S(),
		reflect: reflect,
	}
}

func (e *CurveEngineImpl) GetBGS() int {
	return e.BGS
}

func (e *CurveEngineImpl) GetBFS() int {
	return e.BFS
}

func (e *CurveEngineImpl) GetG1S() int {
	return e.G1S
}

func (e *CurveEngineImpl) GetG2S() int {
	return e.G2S
}

func (e *CurveEngineImpl) GetSecretKeySize() int {
	return e.BGS
}

func (e *CurveEngineImpl) GetPublicKeySize() int {
	return e.G2S
}

func (e *CurveEngineImpl) KeyPairGenerateIKM(IKM []byte) (*KeyPair, error) {
	kp := &KeyPair{
		S: make([]byte, e.BGS),
		W: make([]byte, e.G2S),
	}

	r := e.reflect.KeyPairGenerate(IKM, kp.S, kp.W)
	if r != 0 {
		return nil, errors.New(fmt.Sprintf("KeyPairGenerate failed: %d", r))
	}

	return kp, nil
}

func (e *CurveEngineImpl) KeyPairGenerate(rng *core.RAND) (*KeyPair, error) {
	var IKM [64]byte

	kp := &KeyPair{
		S: make([]byte, e.BGS),
		W: make([]byte, e.G2S),
	}

	for i := 0; i < len(IKM); i++ {
		IKM[i] = byte(rng.GetByte())
	}

	r := e.reflect.KeyPairGenerate(IKM[:], kp.S, kp.W)
	if r != 0 {
		return nil, errors.New(fmt.Sprintf("KeyPairGenerate failed: %d", r))
	}

	return kp, nil
}

func (e *CurveEngineImpl) Sign(M []byte, S []byte) ([]byte, error) {
	sig := make([]byte, e.G1S)
	r := e.reflect.CoreSign(sig, M, S)
	if r != 0 {
		return nil, errors.New(fmt.Sprintf("error: %d", r))
	}
	return sig, nil
}

func (e *CurveEngineImpl) Verify(SIG []byte, M []byte, W []byte) int {
	return e.reflect.CoreVerify(SIG, M, W)
}

func (e *CurveEngineImpl) GeneratePublicKey(S []byte) ([]byte, error) {
	s := e.reflect.FromBytes(S)
	G := e.reflect.ECP8Generator()
	G = e.reflect.G2mul(G, s)
	W := make([]byte, e.G2S)
	G.ToBytes(W, true)
	return W, nil
}
