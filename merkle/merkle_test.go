package merkle

import (
	"fmt"
	"testing"
)

func TestBuildMerkleTree(t *testing.T) {
	hashStr1 := "5fd362bb7fe89969942cafdeaa0b71e726b759e52a256a1d33ef613410d71aaa"
	hashStr2 := "e5f44aafcc241093201d5e67955d562089bf9374bf0313b4947fd3023e85a0ff"
	hashStr3 := "00a8269382dc8d931583e7722f07dc56ee42e2c913d4fd571336966c47b2e115"

	hashes := make([]*Hash, 3)
	hashes[0] = HashStr2Hash(hashStr1)
	hashes[1] = HashStr2Hash(hashStr2)
	hashes[2] = HashStr2Hash(hashStr3)
	merkles := BuildMerkleTree(hashes)

	calculatedMerkleRoot := merkles[len(merkles)-1]
	wantStr := "d142242c39397e6909f6ceb7258cbdae41b029710e35debd7004d25314ddfd42"
	wantMerkle := HashStr2Hash(wantStr)
	if !wantMerkle.IsEqual(calculatedMerkleRoot) {
		t.Errorf("BuildMerkleTree: merkle root mismatch - "+
			"got %x, want %x", *calculatedMerkleRoot, *wantMerkle)
	}
}

func TestVerifyLeafToRoot(t *testing.T) {
	hashStr0 := "5fd362bb7fe89969942cafdeaa0b71e726b759e52a256a1d33ef613410d71aaa"
	hashStr1 := "e5f44aafcc241093201d5e67955d562089bf9374bf0313b4947fd3023e85a0ff"
	hashStr2 := "00a8269382dc8d931583e7722f07dc56ee42e2c913d4fd571336966c47b2e115"
	hashStr3 := "fe703d4b44f8116142115cd36e54b591ff20f471c6349fe4ab47915a13fceea8"
	hashStr4 := "711453e26062ced8919b10264660d983664c5e5f0a6c5dbb4cd65ae58cb381f1"

	hashes := make([]*Hash, 5)
	hashes[0] = HashStr2Hash(hashStr0)
	hashes[1] = HashStr2Hash(hashStr1)
	hashes[2] = HashStr2Hash(hashStr2)
	hashes[3] = HashStr2Hash(hashStr3)
	hashes[4] = HashStr2Hash(hashStr4)

	merkles := BuildMerkleTree(hashes)
	fmt.Println("--------------------------Merkle Tree---------------------------")
	PrintHash(merkles)

	targetHash := HashStr2Hash(hashStr4)
	indexesOfVerifyNodes, verifyNodes := NodesForVerify(targetHash, merkles)
	fmt.Println("--------------------------Nodes for verifying-------------------")
	fmt.Println(indexesOfVerifyNodes)
	PrintHash(verifyNodes)
	fmt.Println("--------------------Verifying from leaf to root------------------")

	res := VerifyLeafToRoot(targetHash, indexesOfVerifyNodes, verifyNodes)
	fmt.Println(res)
	if res != true {
		t.Errorf("Failed")
	}
}
