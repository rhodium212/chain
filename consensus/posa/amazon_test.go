package posa

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

type mockState struct {
	// mock state
	expected map[common.Address]bool
	// testing
	t *testing.T
}

func (state *mockState) SetCode(addr common.Address, code []byte) {
	if !state.expected[addr] {
		state.t.Fatalf("unexpected SetCode(%v)", addr)
	}

	// validate that the code is not empty
	if len(code) == 0 {
		state.t.Fatalf("unexpected empty code for %v", addr)
	}
}

func TestAmazonPatchTestnet(t *testing.T) {

	state := &mockState{
		t: t,
		expected: map[common.Address]bool{
			common.HexToAddress("0x67f6a7BbE0da067A747C6b2bEdF8aBBF7D6f60dc"): true,
			common.HexToAddress("0xD6c7E27a598714c2226404Eb054e0c074C906Fc9"): true,
			common.HexToAddress("0xF8Cb9f1D136Ff4c883320b5B4fa80048b888F459"): true,
			common.HexToAddress("0xf57a7eE19a628e4d475b72d6c9DD847c50636e01"): true,

			// validators contract
			IshikariValidatorsContractAddr: true,
		},
	}

	for _, p := range GetAmazonPatches(big.NewInt(2345)) {
		p(state)
	}

}

func TestAmazonPatchMainnet(t *testing.T) {

	state := &mockState{
		t: t,
		expected: map[common.Address]bool{
			common.HexToAddress("0x0039f574eE5cC39bdD162E9A88e3EB1f111bAF48"): true,
			common.HexToAddress("0x980a5AfEf3D17aD98635F6C5aebCBAedEd3c3430"): true,
			common.HexToAddress("0xfA93C12Cd345c658bc4644D1D4E1B9615952258C"): true,
			common.HexToAddress("0xf55aF137A98607F7ED2eFEfA4cd2DfE70E4253b1"): true,
			common.HexToAddress("0x1B8e27ABA297466fc6765Ce55BD12A8E216759da"): true,

			// validators contract
			IshikariValidatorsContractAddr: true,
		},
	}

	for _, p := range GetAmazonPatches(big.NewInt(234)) {
		p(state)
	}
}
