package headerfs

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// Real BLAKE2b mainnet headers, heights 961640 to 961643, as Bitcoin Knots
// serializes them (164 bytes each).
var blake2bHdrs = []string{
	"000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc7684dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d0300000000000000000000001e0300000000000000000000000000000000000068ac0e000000000000000000000000000000000000000000000000000000000000000000",
	"000000a0eb8ef1961354c8a8e794a4e5464fe13b2959f47296f6e5c150000000000000006639b797171dbe9c48f7d32714d7a3c7d850bfee30772864e4214ed9d80282fea5ce936a4f8d001a7c31a7570cb5e64aa5ce936a00000000b1ccf00d020000000000000000000000120200000000000000000000000000000000000069ac0e000000000000000000000000000000000000000000000000000000000000000000",
	"000000a0b6f7d73ece01f1b9bd60c30eaca12aa88e138cb07d1513ef1000000000000000436e2b1c96830528d1628746b9f381e8af54387737bed44c0689721bbb3fe133a7cf936a4f8d001a710a300fb9b74033a7cf936a00000000b1ccf00d0300000000000000000000001b030000000000000000000000000000000000006aac0e000000000000000000000000000000000000000000000000000000000000000000",
	"000000a06e508af96d0af5b9f8e6fa29b5401b345348c53c3be4dc9b4c000000000000007708d2a21d10c940858b134312573933b0503e168dd589e455c8ba0cc353db1f91d8936a4f8d001ab2fcfe2a36fc591591d8936a0000000059c19ff5080000000000000000000000c8010000000000000000000000000000000000006bac0e000000000000000000000000000000000000000000000000000000000000000000",
}

func decodeHeader(t *testing.T, s string) *wire.BlockHeader {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	var h wire.BlockHeader
	require.NoError(t, h.Deserialize(bytes.NewReader(b)))
	return &h
}

// TestBlockHeaderLayout checks the offsets of a store whose headers become
// 164 bytes wide from a given height, and that the classic layout is what it
// always was.
func TestBlockHeaderLayout(t *testing.T) {
	classic := newBlockHeaderLayout(&chaincfg.SimNetParams)
	require.Equal(t, uint64(80*7), classic.offset(7))
	n, err := classic.count(80 * 7)
	require.NoError(t, err)
	require.Equal(t, uint32(7), n)
	_, err = classic.count(80*7 + 1)
	require.Error(t, err)

	l := blockHeaderLayout{v2Height: 3}
	require.Equal(t, uint64(80*3), l.offset(3))
	require.Equal(t, uint64(80*3+164*2), l.offset(5))
	require.Equal(t, uint32(80), l.size(2))
	require.Equal(t, uint32(164), l.size(3))
	for _, c := range []uint32{0, 1, 3, 4, 9} {
		got, err := l.count(int64(l.offset(c)))
		require.NoError(t, err)
		require.Equal(t, c, got)
	}
	_, err = l.count(80*3 + 80)
	require.Error(t, err)

	mainnet := newBlockHeaderLayout(&chaincfg.MainNetParams)
	require.Equal(t, uint32(961640), mainnet.v2Height)
}

// TestBlockHeaderStoreAcrossBlake2b writes classic headers then v2 ones into
// a store, reads them back one by one and as a range spanning the switch,
// rolls back across it, and reopens the store from its files.
func TestBlockHeaderStoreAcrossBlake2b(t *testing.T) {
	dir := t.TempDir()
	db, err := walletdb.Create(
		"bdb", filepath.Join(dir, "test.db"), true, time.Second*10,
	)
	require.NoError(t, err)
	defer db.Close()

	params := chaincfg.SimNetParams
	params.Blake2bHeight = int32(len(blockHdrs))
	store, err := NewBlockHeaderStore(dir, db, &params)
	require.NoError(t, err)
	bhs := store.(*blockHeaderStore)

	var all []BlockHeader
	for i, s := range blockHdrs {
		all = append(all, BlockHeader{
			BlockHeader: decodeHeader(t, s), Height: uint32(i),
		})
	}
	for i, s := range blake2bHdrs {
		all = append(all, BlockHeader{
			BlockHeader: decodeHeader(t, s),
			Height:      uint32(len(blockHdrs) + i),
		})
	}

	// Genesis was written when the store was created.
	require.NoError(t, bhs.WriteHeaders(all[1:]...))

	// A header of the wrong format for its height is refused.
	tip := uint32(len(all) - 1)
	wrong := BlockHeader{BlockHeader: all[1].BlockHeader, Height: tip + 1}
	require.Error(t, bhs.WriteHeaders(wrong))

	fi, err := os.Stat(filepath.Join(dir, "block_headers.bin"))
	require.NoError(t, err)
	require.Equal(t, int64(80*len(blockHdrs)+164*len(blake2bHdrs)),
		fi.Size())

	for _, h := range all {
		got, err := bhs.FetchHeaderByHeight(h.Height)
		require.NoError(t, err)
		require.Equal(t, h.BlockHash(), got.BlockHash())

		hash := h.BlockHash()
		_, height, err := bhs.FetchHeader(&hash)
		require.NoError(t, err)
		require.Equal(t, h.Height, height)
	}

	rng, err := bhs.readHeaderRange(2, tip)
	require.NoError(t, err)
	require.Len(t, rng, int(tip-1))
	for i, h := range rng {
		require.Equal(t, all[i+2].BlockHash(), h.BlockHash())
	}

	// Roll back over the switch, then write the same headers again.
	stamp, err := bhs.RollbackBlockHeaders(uint32(len(blake2bHdrs) + 1))
	require.NoError(t, err)
	require.Equal(t, int32(len(blockHdrs)-2), stamp.Height)
	require.NoError(t, bhs.WriteHeaders(all[len(blockHdrs)-1:]...))

	// A reopened store finds its tip in the files.
	store, err = NewBlockHeaderStore(dir, db, &params)
	require.NoError(t, err)
	tipHeader, tipHeight, err := store.ChainTip()
	require.NoError(t, err)
	require.Equal(t, tip, tipHeight)
	require.Equal(t, all[tip].BlockHash(), tipHeader.BlockHash())
}

// TestBlockHeaderStoreTrimsPartialRecord checks that a header file ending in
// part of a record (a write cut short) is cut back to its last whole header
// when the store opens, in the classic run and in the v2 run, and that the
// store then appends at the right offset.
func TestBlockHeaderStoreTrimsPartialRecord(t *testing.T) {
	for _, tc := range []struct {
		name    string
		classic int // classic headers written (genesis included)
		v2      int // v2 headers written after them
		junk    int // bytes of a partial record appended
	}{
		{"classic run", len(blockHdrs), 0, 30},
		{"v2 run", len(blockHdrs), len(blake2bHdrs), 100},
		{"first v2 record", len(blockHdrs), 0, 90},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			db, err := walletdb.Create(
				"bdb", filepath.Join(dir, "test.db"), true,
				time.Second*10,
			)
			require.NoError(t, err)
			defer db.Close()

			params := chaincfg.SimNetParams
			params.Blake2bHeight = int32(len(blockHdrs))
			store, err := NewBlockHeaderStore(dir, db, &params)
			require.NoError(t, err)
			bhs := store.(*blockHeaderStore)

			var all []BlockHeader
			for i, s := range blockHdrs {
				all = append(all, BlockHeader{
					BlockHeader: decodeHeader(t, s), Height: uint32(i),
				})
			}
			for i, s := range blake2bHdrs {
				all = append(all, BlockHeader{
					BlockHeader: decodeHeader(t, s),
					Height:      uint32(len(blockHdrs) + i),
				})
			}
			n := tc.classic + tc.v2
			require.NoError(t, bhs.WriteHeaders(all[1:n]...))

			// A cut-short write leaves junk after the last record.
			path := filepath.Join(dir, "block_headers.bin")
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
			require.NoError(t, err)
			_, err = f.Write(bytes.Repeat([]byte{0xab}, tc.junk))
			require.NoError(t, err)
			require.NoError(t, f.Close())

			store, err = NewBlockHeaderStore(dir, db, &params)
			require.NoError(t, err)
			bhs = store.(*blockHeaderStore)
			fi, err := os.Stat(path)
			require.NoError(t, err)
			require.Equal(t, int64(bhs.blockLayout.offset(uint32(n))), fi.Size())

			tip, height, err := store.ChainTip()
			require.NoError(t, err)
			require.EqualValues(t, n-1, height)
			require.Equal(t, all[n-1].BlockHash(), tip.BlockHash())

			// And the next header goes where it belongs.
			if n < len(all) {
				require.NoError(t, bhs.WriteHeaders(all[n]))
				got, err := store.FetchHeaderByHeight(uint32(n))
				require.NoError(t, err)
				require.Equal(t, all[n].BlockHash(), got.BlockHash())
			}
		})
	}
}

// TestBlockHeaderStoreIndexAheadOfFile checks that a store whose index got
// ahead of its file (the last record only partly reached the disk, while the
// index commit did) opens with the index rolled back to the file's tip,
// instead of failing on a truncation count that wrapped around.
func TestBlockHeaderStoreIndexAheadOfFile(t *testing.T) {
	for _, tc := range []struct {
		name string
		v2   int // v2 headers written
		cut  int // bytes cut off the last record
	}{
		{"classic record", 0, 30},
		{"v2 record", len(blake2bHdrs), 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			db, err := walletdb.Create(
				"bdb", filepath.Join(dir, "test.db"), true,
				time.Second*10,
			)
			require.NoError(t, err)
			defer db.Close()

			params := chaincfg.SimNetParams
			params.Blake2bHeight = int32(len(blockHdrs))
			store, err := NewBlockHeaderStore(dir, db, &params)
			require.NoError(t, err)
			bhs := store.(*blockHeaderStore)

			var all []BlockHeader
			for i, s := range blockHdrs {
				all = append(all, BlockHeader{
					BlockHeader: decodeHeader(t, s), Height: uint32(i),
				})
			}
			for i, s := range blake2bHdrs {
				all = append(all, BlockHeader{
					BlockHeader: decodeHeader(t, s),
					Height:      uint32(len(blockHdrs) + i),
				})
			}
			n := len(blockHdrs) + tc.v2
			require.NoError(t, bhs.WriteHeaders(all[1:n]...))

			// The last record only partly made it to the disk.
			path := filepath.Join(dir, "block_headers.bin")
			fi, err := os.Stat(path)
			require.NoError(t, err)
			require.NoError(t, os.Truncate(path, fi.Size()-int64(tc.cut)))

			store, err = NewBlockHeaderStore(dir, db, &params)
			require.NoError(t, err)
			tip, height, err := store.ChainTip()
			require.NoError(t, err)
			require.EqualValues(t, n-2, height)
			require.Equal(t, all[n-2].BlockHash(), tip.BlockHash())

			// The lost header is written again where it belongs.
			bhs = store.(*blockHeaderStore)
			require.NoError(t, bhs.WriteHeaders(all[n-1]))
			got, err := store.FetchHeaderByHeight(uint32(n - 1))
			require.NoError(t, err)
			require.Equal(t, all[n-1].BlockHash(), got.BlockHash())
		})
	}
}

// TestBlockHeaderStoreRefusesOtherBlake2bHeight checks that a header file
// written with one BLAKE2b height is not read with another (a changed
// regtest activation height would read every later record at the wrong
// offset), and that the same height opens fine.
func TestBlockHeaderStoreRefusesOtherBlake2bHeight(t *testing.T) {
	dir := t.TempDir()
	db, err := walletdb.Create(
		"bdb", filepath.Join(dir, "test.db"), true, time.Second*10,
	)
	require.NoError(t, err)
	defer db.Close()

	params := chaincfg.SimNetParams
	params.Blake2bHeight = 5
	_, err = NewBlockHeaderStore(dir, db, &params)
	require.NoError(t, err)

	_, err = NewBlockHeaderStore(dir, db, &params)
	require.NoError(t, err)

	other := params
	other.Blake2bHeight = 4
	_, err = NewBlockHeaderStore(dir, db, &other)
	require.ErrorContains(t, err, "BLAKE2b height 5")

	none := params
	none.Blake2bHeight = 0
	_, err = NewBlockHeaderStore(dir, db, &none)
	require.Error(t, err)
}

// pairedFilterStores opens a block header store and a filter header store on
// one database, as neutrino runs them: the filter store's index entries are
// the block store's. It writes n block headers and their filter headers, and
// returns the filter headers (heights 1 to n).
func pairedFilterStores(t *testing.T, n int) (walletdb.DB, string,
	[]FilterHeader) {

	t.Helper()
	dir := t.TempDir()
	db, err := walletdb.Create(
		"bdb", filepath.Join(dir, "test.db"), true, time.Second*10,
	)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	bS, err := NewBlockHeaderStore(dir, db, &chaincfg.SimNetParams)
	require.NoError(t, err)
	fS, err := NewFilterHeaderStore(
		dir, db, RegularFilter, &chaincfg.SimNetParams, nil,
	)
	require.NoError(t, err)

	prev := *chaincfg.SimNetParams.GenesisHash
	var blocks []BlockHeader
	var filters []FilterHeader
	for i := 1; i <= n; i++ {
		h := &wire.BlockHeader{
			Version: 1, PrevBlock: prev, Nonce: uint32(i),
			Timestamp: time.Unix(int64(1_600_000_000+i), 0),
		}
		blocks = append(blocks, BlockHeader{BlockHeader: h, Height: uint32(i)})
		filters = append(filters, FilterHeader{
			HeaderHash: h.BlockHash(),
			FilterHash: chainhash.DoubleHashH([]byte{byte(i), 0xf1}),
			Height:     uint32(i),
		})
		prev = h.BlockHash()
	}
	require.NoError(t, bS.WriteHeaders(blocks...))
	require.NoError(t, fS.WriteHeaders(filters...))

	return db, dir, filters
}

// TestFilterHeaderStoreIndexAheadOfFile checks that a filter header file cut
// short under a full index opens with the index's tip on the block hash at
// the file's height (the tip key holds block hashes), so the store keeps
// opening and syncs on from there.
func TestFilterHeaderStoreIndexAheadOfFile(t *testing.T) {
	db, dir, hdrs := pairedFilterStores(t, 20)

	// The last two records never reached the disk; the index did.
	path := filepath.Join(dir, "reg_filter_headers.bin")
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.NoError(t, os.Truncate(path, fi.Size()-2*32))

	var fS FilterHeaderStore
	for i := 0; i < 2; i++ { // and it opens again after the repair
		fS, err = NewFilterHeaderStore(
			dir, db, RegularFilter, &chaincfg.SimNetParams, nil,
		)
		require.NoError(t, err)
		tip, height, err := fS.ChainTip()
		require.NoError(t, err)
		require.EqualValues(t, 18, height)
		require.Equal(t, hdrs[17].FilterHash, *tip)
	}

	// The lost headers are written again where they belong.
	require.NoError(t, fS.WriteHeaders(hdrs[18:]...))
	got, err := fS.FetchHeaderByHeight(20)
	require.NoError(t, err)
	require.Equal(t, hdrs[19].FilterHash, *got)
}

// TestFilterHeaderStoreShorterThanARecord checks that a filter header file
// left with less than one whole record starts again from the genesis filter
// header instead of wrapping its height around.
func TestFilterHeaderStoreShorterThanARecord(t *testing.T) {
	db, dir, _ := pairedFilterStores(t, 5)
	fS, err := NewFilterHeaderStore(
		dir, db, RegularFilter, &chaincfg.SimNetParams, nil,
	)
	require.NoError(t, err)
	genesis, err := fS.FetchHeaderByHeight(0)
	require.NoError(t, err)

	path := filepath.Join(dir, "reg_filter_headers.bin")
	require.NoError(t, os.Truncate(path, 20))

	for i := 0; i < 2; i++ {
		fS, err = NewFilterHeaderStore(
			dir, db, RegularFilter, &chaincfg.SimNetParams, nil,
		)
		require.NoError(t, err)
		tip, height, err := fS.ChainTip()
		require.NoError(t, err)
		require.EqualValues(t, 0, height)
		require.Equal(t, *genesis, *tip)
	}
}

// TestBlockHeaderStoreAcceptsEarlierForkV2Store checks that a store from the
// earlier fork (v2 records past the BLAKE2b height, no height recorded) opens
// when the record at the height is a v2 header committing to it, and is still
// refused when that record commits to another height.
func TestBlockHeaderStoreAcceptsEarlierForkV2Store(t *testing.T) {
	for _, tc := range []struct {
		name   string
		commit int // height the v2 record says, relative to the BLAKE2b height
		ok     bool
	}{
		{"commits to the height", 0, true},
		{"commits to another height", 5, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			db, err := walletdb.Create(
				"bdb", filepath.Join(dir, "test.db"), true,
				time.Second*10,
			)
			require.NoError(t, err)
			defer db.Close()

			params := chaincfg.SimNetParams
			params.Blake2bHeight = int32(len(blockHdrs))
			store, err := NewBlockHeaderStore(dir, db, &params)
			require.NoError(t, err)
			bhs := store.(*blockHeaderStore)

			var hdrs []BlockHeader
			for i, s := range blockHdrs[1:] {
				hdrs = append(hdrs, BlockHeader{
					BlockHeader: decodeHeader(t, s), Height: uint32(i + 1),
				})
			}
			// A real v2 header, made to commit to the test's height.
			v2 := decodeHeader(t, blake2bHdrs[0])
			v2.Height = params.Blake2bHeight + int32(tc.commit)
			hdrs = append(hdrs, BlockHeader{
				BlockHeader: v2, Height: uint32(params.Blake2bHeight),
			})
			require.NoError(t, bhs.WriteHeaders(hdrs...))

			// The earlier fork recorded no height.
			require.NoError(t, walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
				return tx.ReadWriteBucket(indexBucket).Delete(blake2bHeightKey)
			}))

			store, err = NewBlockHeaderStore(dir, db, &params)
			if !tc.ok {
				require.ErrorContains(t, err, "classic headers")
				return
			}
			require.NoError(t, err)
			tip, height, err := store.ChainTip()
			require.NoError(t, err)
			require.EqualValues(t, params.Blake2bHeight, height)
			require.Equal(t, v2.BlockHash(), tip.BlockHash())

			// The height is recorded now.
			got, found, err := store.(*blockHeaderStore).layoutHeight()
			require.NoError(t, err)
			require.True(t, found)
			require.EqualValues(t, params.Blake2bHeight, got)
		})
	}
}
