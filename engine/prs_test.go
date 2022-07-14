package engine_test

import (
	"go.bryk.io/miracl/core"
	"testing"
)

func TestCurveEngineImpl_Prs(t *testing.T) {
	rng := core.NewRAND()

	e := NewCurveEngineBLS48581()
	aliceKey, _ := e.KeyPairGenerate(rng)
	bobKey, _ := e.KeyPairGenerate(rng)

	designatedKey, _ := e.PrsDesignatedKey(aliceKey.S, bobKey.W)
	resignKey, _ := e.PrsResigningKey(bobKey.S, aliceKey.W)

	msg := []byte("HELLO WORLD")

	sigAlice, _ := e.Sign(msg, designatedKey)
	sigBob, _ := e.PrsResign(sigAlice, resignKey)

	r := e.Verify(sigBob, msg, bobKey.W)

	if r != 0 {
		t.Errorf("signature verify failed: %d", r)
	}
}
