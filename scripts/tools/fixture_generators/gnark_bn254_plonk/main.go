package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

type mulCircuit struct {
	A frontend.Variable
	B frontend.Variable
	C frontend.Variable `gnark:",public"`
	D frontend.Variable `gnark:",public"`
}

func (c *mulCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.C)
	api.AssertIsEqual(api.Add(c.A, c.B), c.D)
	api.AssertIsEqual(api.Add(c.A, 7), c.B)
	return nil
}

type writerTo interface {
	WriteTo(io.Writer) (int64, error)
}

type rawWriterTo interface {
	WriteRawTo(io.Writer) (int64, error)
}

func writeToBytes(value writerTo) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := value.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeRawToBytes(value rawWriterTo) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := value.WriteRawTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func frToBytes(value fr.Element) []byte {
	var out [32]byte
	var v big.Int
	value.BigInt(&v)
	v.FillBytes(out[:])
	return out[:]
}

func main() {
	outPath := flag.String(
		"out",
		filepath.FromSlash("../../fixtures/plonk_bn254_gnark_receipt.txt"),
		"output fixture path",
	)
	flag.Parse()

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &mulCircuit{})
	if err != nil {
		panic(err)
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(err)
	}

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	assignment := &mulCircuit{
		A: 3,
		B: 10,
		C: 30,
		D: 13,
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}
	if err := plonk.Verify(proof, vk, publicWitness); err != nil {
		panic(err)
	}

	vkBytes, err := writeToBytes(vk)
	if err != nil {
		panic(err)
	}
	if len(vkBytes) < 8 {
		panic("vk bytes too short to normalize commitment index length")
	}
	// gnark-bn254-verifier expects a u64-length trailer for commitment indexes.
	// This fixture has none, so normalize the final 8 bytes to zero.
	for i := len(vkBytes) - 8; i < len(vkBytes); i++ {
		vkBytes[i] = 0
	}
	proofBytes, err := writeRawToBytes(proof)
	if err != nil {
		panic(err)
	}

	pubVector, ok := publicWitness.Vector().(fr.Vector)
	if !ok {
		panic("unexpected public witness vector type")
	}
	var pubInputs []byte
	for i := range pubVector {
		pubInputs = append(pubInputs, frToBytes(pubVector[i])...)
	}

	payload := fmt.Sprintf(
		"vk_hex=%s\nproof_hex=%s\npub_inputs_hex=%s\n",
		hex.EncodeToString(vkBytes),
		hex.EncodeToString(proofBytes),
		hex.EncodeToString(pubInputs),
	)

	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(*outPath, []byte(payload), 0o644); err != nil {
		panic(err)
	}
}
