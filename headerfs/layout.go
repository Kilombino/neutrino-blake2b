package headerfs

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

// blockHeaderLayout places block headers in the flat file. On a chain with
// BLAKE2b proof of work (chaincfg.Params.Blake2bHeight), every header from that
// height on is a 164-byte "header v2" and every one before it an 80-byte
// classic header, so the file holds two runs of fixed-size records: the
// offset of any height is still a closed formula and random access stays one
// read. On every other chain the layout is the classic one, 80 bytes per
// header, and a file written before this layout existed reads the same.
type blockHeaderLayout struct {
	// v2Height is the first height stored as a v2 header; zero means
	// none is.
	v2Height uint32
}

func newBlockHeaderLayout(params *chaincfg.Params) blockHeaderLayout {
	if params == nil || params.Blake2bHeight <= 0 {
		return blockHeaderLayout{}
	}
	return blockHeaderLayout{v2Height: uint32(params.Blake2bHeight)}
}

// isV2 reports whether the header at this height is stored as a v2 header.
func (l blockHeaderLayout) isV2(height uint32) bool {
	return l.v2Height != 0 && height >= l.v2Height
}

// size is the number of bytes of the header at this height.
func (l blockHeaderLayout) size(height uint32) uint32 {
	if l.isV2(height) {
		return wire.BlockHeaderLenV2
	}
	return wire.BlockHeaderLenV1
}

// offset is where the header at this height starts; offset(n) is the size
// of a file holding heights 0 to n-1.
func (l blockHeaderLayout) offset(height uint32) uint64 {
	if !l.isV2(height) {
		return uint64(height) * wire.BlockHeaderLenV1
	}
	return uint64(l.v2Height)*wire.BlockHeaderLenV1 +
		uint64(height-l.v2Height)*wire.BlockHeaderLenV2
}

// count is the number of headers in a file of this size, refusing a size that
// does not end on a record boundary.
func (l blockHeaderLayout) count(fileSize int64) (uint32, error) {
	size := uint64(fileSize)
	classic := uint64(l.v2Height) * wire.BlockHeaderLenV1
	if l.v2Height == 0 || size <= classic {
		if size%wire.BlockHeaderLenV1 != 0 {
			return 0, fmt.Errorf("block header file of %d bytes "+
				"does not hold whole headers", size)
		}
		return uint32(size / wire.BlockHeaderLenV1), nil
	}
	if (size-classic)%wire.BlockHeaderLenV2 != 0 {
		return 0, fmt.Errorf("block header file of %d bytes does not "+
			"hold whole headers (v2 from height %d)", size,
			l.v2Height)
	}
	return l.v2Height + uint32((size-classic)/wire.BlockHeaderLenV2), nil
}

// whole is the number of whole headers in a file of this size, and the size
// those headers take: a partial record at the end is left out.
func (l blockHeaderLayout) whole(fileSize int64) (uint32, int64) {
	size := uint64(fileSize)
	classic := uint64(l.v2Height) * wire.BlockHeaderLenV1
	if l.v2Height == 0 || size <= classic {
		n := size / wire.BlockHeaderLenV1
		return uint32(n), int64(n * wire.BlockHeaderLenV1)
	}
	n := (size - classic) / wire.BlockHeaderLenV2
	return l.v2Height + uint32(n), int64(classic + n*wire.BlockHeaderLenV2)
}

// check refuses a header whose format is not the one its height is stored in:
// writing it would shift every record after it.
func (l blockHeaderLayout) check(header *wire.BlockHeader, height uint32) error {
	if header.IsV2() != l.isV2(height) {
		return fmt.Errorf("block header at height %d is v2=%v, the "+
			"store expects v2=%v", height, header.IsV2(),
			l.isV2(height))
	}
	return nil
}
