package engine

import (
	"go.bryk.io/miracl/core/BLS48581"
)

func (e *CurveEngineImpl) prsEcdh(S []byte, W []byte) (*KeyPair, error) {
	s := e.reflect.FromBytes(S)
	w := e.reflect.ECP8FromBytes(W)

	t := e.reflect.G2mul(w, s)
	t.Affine()

	dhPoint := make([]byte, e.G2S)
	t.ToBytes(dhPoint, true)

	kp, err := e.KeyPairGenerateIKM(dhPoint)
	if err != nil {
		return nil, err
	}

	return kp, nil
}

func (e *CurveEngineImpl) PrsDesignatedKey(S []byte, W []byte) ([]byte, error) {
	kp, err := e.prsEcdh(S, W)
	if err != nil {
		return nil, err
	}
	return kp.S, err
}

func (e *CurveEngineImpl) PrsResigningKey(S []byte, W []byte) ([]byte, error) {
	r := e.reflect.BIGCurveOrder()
	s := e.reflect.FromBytes(S)

	dk, err := e.prsEcdh(S, W)
	if err != nil {
		return nil, err
	}

	inverseS := e.reflect.FromBytes(dk.S)
	inverseS.Invmodp(r)

	t := e.reflect.Modmul(s, inverseS, r)
	t.ToBytes(dk.S[:])

	return dk.S, nil
}

func (e *CurveEngineImpl) PrsResign(inSig []byte, S []byte) ([]byte, error) {
	s := BLS48581.FromBytes(S)
	P := BLS48581.ECP_fromBytes(inSig)
	P = P.Mul(s)

	outSig := make([]byte, e.G1S)
	P.ToBytes(outSig, true)

	return outSig, nil
}
