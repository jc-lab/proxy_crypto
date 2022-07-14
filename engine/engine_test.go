package engine_test

import (
	"github.com/jc-lab/miracl_wrapper"
	"github.com/jc-lab/proxy_crypto/engine"
	"go.bryk.io/miracl/core"
	"go.bryk.io/miracl/core/BLS48581"
	"testing"
)

func NewCurveReflectWithBLS48581() miracl_wrapper.CurveReflect {
	BLS48581.Init()
	return miracl_wrapper.NewCurveReflect(&miracl_wrapper.CurveFunctions{
		BGS:             BLS48581.BGS,
		BFS:             BLS48581.BFS,
		KeyPairGenerate: BLS48581.KeyPairGenerate,
		CoreSign:        BLS48581.Core_Sign,
		CoreVerify:      BLS48581.Core_Verify,
		ECP8Generator:   BLS48581.ECP8_generator,
		ECP8FromBytes:   BLS48581.ECP8_fromBytes,
		FromBytes:       BLS48581.FromBytes,
		G2mul:           BLS48581.G2mul,
		BIGCurveOrder: func() any {
			return BLS48581.NewBIGints(BLS48581.CURVE_Order)
		},
		Modmul: BLS48581.Modmul,
	})
}

func NewCurveEngineBLS48581() engine.CurveEngine {
	return engine.NewCurveEngine(NewCurveReflectWithBLS48581())
}

func TestCurveEngineImpl_KeyPairGenerate(t *testing.T) {
	e := NewCurveEngineBLS48581()
	rng := core.NewRAND()
	kp, err := e.KeyPairGenerate(rng)
	if err != nil {
		t.Error(err)
		return
	}

	if len(kp.S) <= 0 {
		t.Error("len(S) is empty")
	}

	if len(kp.W) <= 0 {
		t.Error("len(W) is empty")
	}
}
