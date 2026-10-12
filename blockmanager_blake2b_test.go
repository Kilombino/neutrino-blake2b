package neutrino

import (
	"reflect"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightninglabs/neutrino/banman"
	"github.com/lightninglabs/neutrino/headerfs"
	"github.com/stretchr/testify/require"
)

// mineClassic returns a classic (80-byte) header on top of prev that meets
// the network's minimum difficulty.
func mineClassic(t *testing.T, params *chaincfg.Params, prev *wire.BlockHeader) *wire.BlockHeader {
	t.Helper()
	h := &wire.BlockHeader{
		Version:    4,
		PrevBlock:  prev.BlockHash(),
		MerkleRoot: chainhash.Hash{1},
		Timestamp:  prev.Timestamp.Add(time.Minute),
		Bits:       params.PowLimitBits,
	}
	target := blockchain.CompactToBig(params.PowLimitBits)
	for {
		hash := h.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(target) <= 0 {
			return h
		}
		h.Nonce++
	}
}

// TestHandleHeadersBansSHA256dPeer checks that a peer sending a classic header
// at or past the BLAKE2b height (a peer on the SHA256d chain) is banned, so it
// is not dialled again.
func TestHandleHeadersBansSHA256dPeer(t *testing.T) {
	t.Parallel()

	params := chaincfg.SimNetParams
	params.Blake2bHeight = 3
	params.Blake2bTargetShift = 20

	dir := t.TempDir()
	db, err := walletdb.Create("bdb", dir+"/weks.db", true, dbOpenTimeout)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	hdrStore, err := headerfs.NewBlockHeaderStore(dir, db, &params)
	require.NoError(t, err)
	cfStore, err := headerfs.NewFilterHeaderStore(
		dir, db, headerfs.RegularFilter, &params, nil,
	)
	require.NoError(t, err)

	var banned []string
	var reasons []banman.Reason
	bm, err := newBlockManager(&blockManagerCfg{
		ChainParams:      params,
		BlockHeaders:     hdrStore,
		RegFilterHeaders: cfStore,
		QueryDispatcher:  &mockDispatcher{},
		TimeSource:       blockchain.NewMedianTime(),
		BanPeer: func(addr string, r banman.Reason) error {
			banned = append(banned, addr)
			reasons = append(reasons, r)
			return nil
		},
	})
	require.NoError(t, err)

	fakePeer, err := peer.NewOutboundPeer(&peer.Config{}, "sha256d:8333")
	require.NoError(t, err)
	disconnected := func() bool {
		return reflect.ValueOf(fakePeer).Elem().
			FieldByName("disconnect").Int() == 1
	}

	// Heights 1 and 2 are below the BLAKE2b height: classic is right.
	h1 := mineClassic(t, &params, &params.GenesisBlock.Header)
	h2 := mineClassic(t, &params, h1)
	// Height 3 must be a v2 header; this peer still sends a classic one.
	h3 := mineClassic(t, &params, h2)

	bm.handleHeadersMsg(&headersMsg{
		headers: &wire.MsgHeaders{Headers: []*wire.BlockHeader{h1, h2, h3}},
		peer:    &ServerPeer{Peer: fakePeer},
	})

	require.Equal(t, []string{"sha256d:8333"}, banned)
	require.Equal(t, []banman.Reason{banman.InvalidBlock}, reasons)
	require.True(t, disconnected())
}
