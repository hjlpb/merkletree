package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
)

const HashSize = 32

type Hash [HashSize]byte

// 判断两个Hash是否相等
func (hash *Hash) IsEqual(target *Hash) bool {
	if hash == nil && target == nil {
		return true
	}
	if hash == nil || target == nil {
		return false
	}
	return *hash == *target
}

//打印哈希数组
func PrintHash(hashes []*Hash) {
	for i, h := range hashes {
		// 如果为nil，需单独处理
		if h == nil {
			fmt.Printf("%d: nil \n", i)
		} else {
			fmt.Printf("%d: %x \n", i, *h)
		}
	}
}

//将hash字符串转换为Hash类型
func HashStr2Hash(hashStr string) *Hash {
	hashTemp, _ := hex.DecodeString(hashStr)
	var hashByte [32]byte
	copy(hashByte[:], hashTemp)
	hash := Hash(hashByte)
	return &hash
}

// 计算大于n的最小的2的幂数
func nextPowerOfTwo(n int) int {
	// 如果n已经是2的幂数，直接返回
	if n&(n-1) == 0 {
		return n
	}
	// 计算log2(n) ，加1
	exponent := uint(math.Log2(float64(n))) + 1
	return 1 << exponent // 2^exponent
}

func DoubleHashH(b []byte) Hash {
	first := sha256.Sum256(b)
	return Hash(sha256.Sum256(first[:]))
}

// 计算两个子节点的父节点的哈希
func HashMerkleBranches(left *Hash, right *Hash) *Hash {
	// 合并两个子节点哈希
	var hash [HashSize * 2]byte
	copy(hash[:HashSize], left[:])
	copy(hash[HashSize:], right[:])

	newHash := DoubleHashH(hash[:])
	return &newHash
}

//	         root = h1234 = h(h12 + h34)
//	        /                           \
//	  h12 = h(h1 + h2)            h34 = h(h3 + h4)
//	   /            \              /            \
//	h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
//
// 	树存储方式：[h1 h2 h3 h4 h12 h34 root]
//  以一组哈希值为叶子结点，构建哈希树
func BuildMerkleTree(hashes []*Hash) []*Hash {
	// 叶子节点数补齐为2的幂数
	nextPoT := nextPowerOfTwo(len(hashes))
	// 总节点数为叶子节点数的2倍减1
	arraySize := nextPoT*2 - 1
	merkles := make([]*Hash, arraySize)
	// 先用待计算哈希值填充
	copy(merkles, hashes)

	// 从倒数第二层开始填充
	offset := nextPoT
	// 从叶子节点开始隔一个节点遍历，相当于遍历所有左节点
	for i := 0; i < arraySize-1; i += 2 {
		switch {
		// When there is no left child node, the parent is nil too.
		// 如果左节点为nil，则父节点也为nil
		case merkles[i] == nil:
			merkles[offset] = nil

		// 如果左节点存在，但右节点不存在，则将左节点复制至右节点
		case merkles[i+1] == nil:
			newHash := HashMerkleBranches(merkles[i], merkles[i])
			merkles[offset] = newHash

		//默认情况，即两个子节点都存在的情况
		default:
			newHash := HashMerkleBranches(merkles[i], merkles[i+1])
			merkles[offset] = newHash
		}
		offset++
	}
	return merkles
}

// 计算验证某个叶子节点是否存在所需要的其他节点
// 输入：构建好的merkle树和要验证的叶子节点哈希值
// 输出：验证节点在merkle树中的索引构成的数组，以及对应的哈希数组
func NodesForVerify(target *Hash, merkles []*Hash) ([]int, []*Hash) {
	//验证节点的数量就是merkle树的深度
	numOfVerifyNodes := uint(math.Log2(float64(len(merkles) + 1)))
	numOfLeafNodes := (len(merkles) + 1) / 2

	// 前者存储验证节点在merkle树中的索引
	// 后者存储对应的哈希
	indexesOfVerifyNodes := make([]int, numOfVerifyNodes)
	verifyNodes := make([]*Hash, numOfVerifyNodes)

	// 首先判断target在树中的索引
	indexOfTarget := -1
	for i, h := range merkles {
		if h.IsEqual(target) {
			indexOfTarget = i
			break
		}
	}
	// 如果没有找到target，则报错
	if indexOfTarget == -1 {
		fmt.Println("Not found the target hash in the merkle tree nodes")
		return nil, nil
	}

	// 单独处理叶子节点那一层
	// 索引为偶数表示左节点，奇数表示右节点
	// 左节点的话，则将对应的右节点填充至验证节点数组
	// 右节点的话，则将对应的左节点填充至验证节点数组
	if indexOfTarget%2 == 0 {
		indexesOfVerifyNodes[0] = indexOfTarget + 1
		verifyNodes[0] = merkles[indexOfTarget+1]
	} else {
		indexesOfVerifyNodes[0] = indexOfTarget - 1
		verifyNodes[0] = merkles[indexOfTarget-1]
	}

	// 验证节点个数（也就是树的深度）如果小于等于2，跳过此部分，直接去将merkle的根节点添加进来
	// 大于2，表示最底层和根节点之间至少有一层
	if numOfVerifyNodes > 2 {
		// 首先找到目标哈希值的所有父节点在各层的索引，对应的验证节点就是每层父节点的左或者右节点
		// 不需要考虑根节点所在层，因此数组长度减1
		indexInEachLevel := make([]int, numOfVerifyNodes-1)
		indexInEachLevel[0] = indexOfTarget
		// offset用于记录每一层的起始索引
		offset := numOfLeafNodes
		for i := 1; i < int(numOfVerifyNodes-1); i++ {
			// 首先提取前一层的索引值
			// 往上一层的索引值（基于当前层）可以根据前一层的索引值计算
			t := indexInEachLevel[i-1]
			if t%2 == 0 {
				indexInEachLevel[i] = t / 2
			} else {
				indexInEachLevel[i] = (t - 1) / 2
			}

			//如果节点在该层的索引为偶数，则对应的验证节点为+1
			//如果节点在该层的索引为奇数，则对应的验证节点为-1
			//在整个merkle中的索引值：所在的层的偏移起始值 + 在该层的索引值
			if indexInEachLevel[i]%2 == 0 {
				indexesOfVerifyNodes[i] = offset + indexInEachLevel[i] + 1
			} else {
				indexesOfVerifyNodes[i] = offset + indexInEachLevel[i] - 1
			}
			// 通过在merkle树中的索引计算找到对应的hash
			verifyNodes[i] = merkles[indexesOfVerifyNodes[i]]
			// offset逐层增加，增量每次减半
			offset += (numOfLeafNodes / (i * 2))
		}
	}

	// 单独添加根节点
	indexesOfVerifyNodes[numOfVerifyNodes-1] = len(merkles) - 1
	verifyNodes[numOfVerifyNodes-1] = merkles[len(merkles)-1]

	return indexesOfVerifyNodes, verifyNodes
}

// 验证根哈希是否一致
// 输入：待验证哈希，验证节点在merkle树中的索引，验证节点的哈希值
func VerifyLeafToRoot(targetHash *Hash, indexesOfVerifyNodes []int, verifyNodes []*Hash) bool {
	// temp用来临时存储两节点哈希结果
	temp := targetHash
	for i, h := range verifyNodes {
		// 如果是根节点，则判断和temp是否一致
		if i == len(verifyNodes)-1 {
			return temp.IsEqual(verifyNodes[i])
		}

		// 有的验证节点hash可能为nil，因此需要判断
		if h != nil {
			//如果验证节点索引为偶数，则验证节点作为左节点，否则作为右节点
			if indexesOfVerifyNodes[i]%2 == 0 {
				temp = HashMerkleBranches(verifyNodes[i], temp)
			} else {
				temp = HashMerkleBranches(temp, verifyNodes[i])
			}
		} else {
			// 如果是空哈希，则直接复制另外一个节点再哈希
			temp = HashMerkleBranches(temp, temp)
		}
		fmt.Printf("%d: %x \n", i, *temp)
	}
	return false
}
