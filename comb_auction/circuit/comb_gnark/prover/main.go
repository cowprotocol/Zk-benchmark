package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	frmimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"

	comb "github.com/cowprotocol/Zk-benchmark/comb_auction/gnark"
)

const (
	DS_R     = 0xA11CE001
	DS_RPAIR = 0xA11CE002
	DS_ALPHA = 0xA11CE003
)

type AuctionsFile struct {
	Range struct {
		AuctionStart int `json:"auction_start"`
		AuctionEnd   int `json:"auction_end"`
	} `json:"range"`
	Auctions []Auction `json:"auctions"`
}

type Auction struct {
	AuctionID int        `json:"auction_id"`
	Solutions []Solution `json:"solutions"`
}

type Solution struct {
	SolutionUID int     `json:"solution_uid"`
	Solver      string  `json:"solver"`
	Trades      []Trade `json:"trades"`
}

type Trade struct {
	OrderUID           string `json:"order_uid"`
	SellToken          string `json:"sell_token"`
	BuyToken           string `json:"buy_token"`
	LimitSell          string `json:"limit_sell"`
	LimitBuy           string `json:"limit_buy"`
	ExecSell           string `json:"exec_sell"`
	ExecBuy            string `json:"exec_buy"`
	Side               int    `json:"side"` // 0 sell, 1 buy
	BuyTokenPriceE18   string `json:"buy_token_price_e18"`
	ScoreNativeIgnored string `json:"score_native"`
}

type Config struct {
	AuctionStart int
	AuctionEnd   int
	AuctionIndex int

	FetchPy string
	UvCmd   string

	CSPath string
	PKPath string
	VKPath string

	OutProof string
	DoVerify bool
}

func main() {
	cfg := Config{}
	flag.IntVar(&cfg.AuctionStart, "auction_start", 0, "auction start id (inclusive)")
	flag.IntVar(&cfg.AuctionEnd, "auction_end", 0, "auction end id (inclusive)")
	flag.IntVar(&cfg.AuctionIndex, "auction_index", -1, "0-based index in exported auctions list")

	flag.StringVar(&cfg.FetchPy, "fetch_py", repoPath("../../../data/fetch.py"), "path to fetch.py")

	flag.StringVar(&cfg.UvCmd, "uv", "uv", "uv executable")

	flag.StringVar(&cfg.CSPath, "cs", repoPath("../circuit.r1cs"), "compiled r1cs")
	flag.StringVar(&cfg.PKPath, "pk", repoPath("../comb_auction.g16.pk"), "proving key")
	flag.StringVar(&cfg.VKPath, "vk", repoPath("../comb_auction.g16.vk"), "verifying key")
	flag.StringVar(&cfg.OutProof, "out", repoPath("../proof.json"), "output proof json")

	flag.BoolVar(&cfg.DoVerify, "verify", true, "verify proof locally with vk")

	flag.Parse()

	if cfg.AuctionStart == 0 || cfg.AuctionEnd == 0 || cfg.AuctionIndex < 0 {
		log.Fatalf("usage: --auction_start <int> --auction_end <int> --auction_index <int>")
	}

	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

func run(cfg Config) error {
	auctionsPath := repoPath("../../../data/" + fmt.Sprintf("auctions_%d_%d.json", cfg.AuctionStart, cfg.AuctionEnd))
	if !fileExists(auctionsPath) {
		fmt.Printf("[i] %s not found; running fetch...\n", auctionsPath)
		if err := runFetch(cfg, auctionsPath); err != nil {
			return err
		}
	}

	data, err := os.ReadFile(auctionsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", auctionsPath, err)
	}

	var af AuctionsFile
	if err := json.Unmarshal(data, &af); err != nil {
		return fmt.Errorf("unmarshal auctions json: %w", err)
	}

	if cfg.AuctionIndex < 0 || cfg.AuctionIndex >= len(af.Auctions) {
		return fmt.Errorf("auction_index out of bounds: got %d, valid [0..%d]", cfg.AuctionIndex, len(af.Auctions)-1)
	}
	auc := af.Auctions[cfg.AuctionIndex]
	fmt.Printf("[i] auction_index=%d -> auction_id=%d (solutions=%d)\n", cfg.AuctionIndex, auc.AuctionID, len(auc.Solutions))

	assignment, publicInputs, err := buildWitnessForAuction(auc)
	if err != nil {
		return err
	}

	fullW, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("frontend.NewWitness: %w", err)
	}
	pubW, err := fullW.Public()
	if err != nil {
		return fmt.Errorf("fullW.Public: %w", err)
	}

	// Load CS + PK
	cs := groth16.NewCS(ecc.BN254)
	if err := readFromFile(cfg.CSPath, cs); err != nil {
		return fmt.Errorf("read cs: %w", err)
	}
	pk, err := loadProvingKey(cfg.PKPath)
	if err != nil {
		return fmt.Errorf("read pk: %w", err)
	}

	fmt.Printf("Proving (public inputs=%d)\n", len(publicInputs))
	proof, err := proveWithAccel(cs, pk, fullW)
	if err != nil {
		return fmt.Errorf("groth16.Prove: %w", err)
	}
	fmt.Println("Proof generated")

	if cfg.DoVerify {
		vk := groth16.NewVerifyingKey(ecc.BN254)
		if err := readFromFile(cfg.VKPath, vk); err != nil {
			return fmt.Errorf("read vk: %w", err)
		}
		if err := groth16.Verify(proof, vk, pubW); err != nil {
			return fmt.Errorf("local verify failed: %w", err)
		}
		fmt.Println("Local verification passed")
	}

	out, err := solidityProofJSON(proof, pubW)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfg.OutProof, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", cfg.OutProof, err)
	}
	fmt.Println("Wrote:", cfg.OutProof)
	return nil
}

func runFetch(cfg Config, auctionsPath string) error {
	cmd := exec.Command(cfg.UvCmd, "run", cfg.FetchPy,
		"--auction_start", fmt.Sprintf("%d", cfg.AuctionStart),
		"--auction_end", fmt.Sprintf("%d", cfg.AuctionEnd),
		"--auction_index", fmt.Sprintf("%d", cfg.AuctionIndex),
	)
	cmd.Dir = filepath.Dir(auctionsPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("fetch command failed: %w", err)
	}
	if !fileExists(auctionsPath) {
		return fmt.Errorf("fetch finished but %s still missing", auctionsPath)
	}
	return nil
}

type SolnBuilt struct {
	SolutionID *big.Int
	SolverAddr *big.Int

	Trades []TradeBuilt

	PairsLen     int
	PairKey      []*big.Int
	PairScore    []*big.Int
	TradePairIdx []int

	TotalScore *big.Int

	Survives bool
}

type TradeBuilt struct {
	TradeID     *big.Int
	SellToken   *big.Int
	BuyToken    *big.Int
	LimitSell   *big.Int
	LimitBuy    *big.Int
	ExecSell    *big.Int
	ExecBuy     *big.Int
	Side        int
	PriceE18    *big.Int
	ScoreNative *big.Int
}

func buildWitnessForAuction(auc Auction) (*comb.Circuit, []*big.Int, error) {
	auctionIDBI := big.NewInt(int64(auc.AuctionID))

	r := mimcFrElems(frFromBig(auctionIDBI), frFromBig(big.NewInt(DS_R)))
	rPair := mimcFrElems(frFromBig(auctionIDBI), frFromBig(big.NewInt(DS_RPAIR)))

	built := make([]SolnBuilt, 0, len(auc.Solutions))
	for _, s := range auc.Solutions {
		sb, err := buildOneSolution(s, auctionIDBI, rPair)
		if err != nil {
			return nil, nil, fmt.Errorf("solution_uid=%d: %w", s.SolutionUID, err)
		}
		built = append(built, sb)
	}

	if len(built) > comb.NMax {
		return nil, nil, fmt.Errorf("auction has %d solutions > NMax=%d; cannot build witness", len(built), comb.NMax)
	}

	// Sort by score descending, assign sequential SolutionIDs.
	// This ensures Solutions[] is ordered by SolutionID ascending AND
	// survivors in packed[] are score-descending, satisfying both circuit constraints.
	sort.Slice(built, func(i, j int) bool {
		return built[i].TotalScore.Cmp(built[j].TotalScore) > 0
	})
	for i := range built {
		built[i].SolutionID = big.NewInt(int64(i))
	}

	applyBaselineFilter(built)

	// Survivors are already in score-descending order (built is sorted above).
	survivors := make([]SolnBuilt, 0, len(built))
	for _, sb := range built {
		if sb.Survives && sb.PairsLen > 0 {
			survivors = append(survivors, sb)
		}
	}

	winners := greedyWinners(survivors, comb.WMax)

	bidsetRoot, err := computeBidsetRoot(built, r)
	if err != nil {
		return nil, nil, err
	}

	asn := new(comb.Circuit)
	asn.AuctionID = auctionIDBI
	asn.BidsetRoot = bidsetRoot

	asn.SolutionsLen = big.NewInt(int64(len(built)))

	asn.WinnersLen = big.NewInt(int64(len(winners)))
	for i := 0; i < comb.WMax; i++ {
		asn.Winners[i].SolutionID = big.NewInt(0)
		asn.Winners[i].Solver = big.NewInt(0)
		asn.Winners[i].Score = big.NewInt(0)
	}
	for i := 0; i < len(winners); i++ {
		asn.Winners[i].SolutionID = winners[i].SolutionID
		asn.Winners[i].Solver = winners[i].SolverAddr
		asn.Winners[i].Score = winners[i].TotalScore
	}

	for i := 0; i < comb.NMax; i++ {
		asn.Solutions[i].SolutionID.Value = big.NewInt(0)
		asn.Solutions[i].Solver.Value = big.NewInt(0)
		asn.Solutions[i].TradesLen = big.NewInt(0)
		asn.Solutions[i].PairsLen = big.NewInt(0)
		for t := 0; t < comb.TMax; t++ {
			asn.Solutions[i].Trades[t].ID = big.NewInt(0)
			asn.Solutions[i].Trades[t].SellToken.Value = big.NewInt(0)
			asn.Solutions[i].Trades[t].BuyToken.Value = big.NewInt(0)
			asn.Solutions[i].Trades[t].SellAmount = big.NewInt(0)
			asn.Solutions[i].Trades[t].BuyAmount = big.NewInt(0)
			asn.Solutions[i].Trades[t].ExecutedSell = big.NewInt(0)
			asn.Solutions[i].Trades[t].ExecutedBuy = big.NewInt(0)
			asn.Solutions[i].Trades[t].Side = big.NewInt(0)
			asn.Solutions[i].Trades[t].NativePriceBuy = big.NewInt(0)
			asn.Solutions[i].TradePairIdx[t] = big.NewInt(0)
		}
		for p := 0; p < comb.PairMax; p++ {
			asn.Solutions[i].PairKey[p] = big.NewInt(0)
			asn.Solutions[i].PairScore[p] = big.NewInt(0)
		}
	}

	for i, sb := range built {
		asn.Solutions[i].SolutionID.Value = sb.SolutionID
		asn.Solutions[i].Solver.Value = sb.SolverAddr
		asn.Solutions[i].TradesLen = big.NewInt(int64(len(sb.Trades)))
		asn.Solutions[i].PairsLen = big.NewInt(int64(sb.PairsLen))

		for t := 0; t < len(sb.Trades) && t < comb.TMax; t++ {
			tr := sb.Trades[t]
			asn.Solutions[i].Trades[t].ID = tr.TradeID
			asn.Solutions[i].Trades[t].SellToken.Value = tr.SellToken
			asn.Solutions[i].Trades[t].BuyToken.Value = tr.BuyToken
			asn.Solutions[i].Trades[t].SellAmount = tr.LimitSell
			asn.Solutions[i].Trades[t].BuyAmount = tr.LimitBuy
			asn.Solutions[i].Trades[t].ExecutedSell = tr.ExecSell
			asn.Solutions[i].Trades[t].ExecutedBuy = tr.ExecBuy
			asn.Solutions[i].Trades[t].Side = big.NewInt(int64(tr.Side))
			asn.Solutions[i].Trades[t].NativePriceBuy = tr.PriceE18
			asn.Solutions[i].TradePairIdx[t] = big.NewInt(int64(sb.TradePairIdx[t]))
		}
		for p := 0; p < sb.PairsLen && p < comb.PairMax; p++ {
			asn.Solutions[i].PairKey[p] = sb.PairKey[p]
			asn.Solutions[i].PairScore[p] = sb.PairScore[p]
		}
	}

	pubVec, err := publicInputsBigints(asn)
	if err != nil {
		return nil, nil, err
	}

	_ = rPair
	_ = r

	return asn, pubVec, nil
}

func buildOneSolution(s Solution, auctionIDBI *big.Int, rPair fr.Element) (SolnBuilt, error) {
	sb := SolnBuilt{
		SolutionID: big.NewInt(int64(s.SolutionUID)),
		SolverAddr: mustAddrToBig(s.Solver),
	}

	alpha := mimcFrElems(
		frFromBig(auctionIDBI),
		frFromBig(big.NewInt(DS_ALPHA)),
		frFromBig(sb.SolverAddr),
		frFromBig(sb.SolutionID),
	)
	_ = alpha

	if len(s.Trades) > comb.TMax {
		return SolnBuilt{}, fmt.Errorf("trades=%d > TMax=%d; cannot prove (increase TMax or skip)", len(s.Trades), comb.TMax)
	}

	type bucket struct {
		key   *big.Int
		score *big.Int
	}
	buckets := []bucket{}
	bucketIndex := map[string]int{}

	sb.Trades = make([]TradeBuilt, 0, len(s.Trades))
	sb.TradePairIdx = make([]int, 0, len(s.Trades))
	sb.TotalScore = big.NewInt(0)

	for _, tr := range s.Trades {
		tb, err := buildTrade(tr)
		if err != nil {
			return SolnBuilt{}, err
		}

		keyFr := frAdd(
			frFromBig(tb.SellToken),
			frMul(rPair, frFromBig(tb.BuyToken)),
		)
		keyBI := frToBig(keyFr)
		keyStr := keyBI.String()

		idx, ok := bucketIndex[keyStr]
		if !ok {
			if len(buckets) >= comb.PairMax {
				return SolnBuilt{}, fmt.Errorf("distinct directed pairs exceed PairMax=%d; cannot prove", comb.PairMax)
			}
			idx = len(buckets)
			bucketIndex[keyStr] = idx
			buckets = append(buckets, bucket{key: keyBI, score: big.NewInt(0)})
		}

		buckets[idx].score.Add(buckets[idx].score, tb.ScoreNative)
		sb.TotalScore.Add(sb.TotalScore, tb.ScoreNative)

		sb.Trades = append(sb.Trades, tb)
		sb.TradePairIdx = append(sb.TradePairIdx, idx)
	}

	sb.PairsLen = len(buckets)
	sb.PairKey = make([]*big.Int, sb.PairsLen)
	sb.PairScore = make([]*big.Int, sb.PairsLen)
	for i := 0; i < sb.PairsLen; i++ {
		sb.PairKey[i] = buckets[i].key
		sb.PairScore[i] = buckets[i].score
	}

	sb.Survives = true
	return sb, nil
}

func buildTrade(t Trade) (TradeBuilt, error) {
	tb := TradeBuilt{
		TradeID:   frToBig(frFromKeccakHex(t.OrderUID)),
		SellToken: mustAddrToBig(t.SellToken),
		BuyToken:  mustAddrToBig(t.BuyToken),
		Side:      t.Side,
	}

	tb.LimitSell = mustDecToBig(t.LimitSell)
	tb.LimitBuy = mustDecToBig(t.LimitBuy)
	tb.ExecSell = mustDecToBig(t.ExecSell)
	tb.ExecBuy = mustDecToBig(t.ExecBuy)
	tb.PriceE18 = mustDecToBig(t.BuyTokenPriceE18)

	tb.ScoreNative = computeScoreNativeGo(
		tb.LimitSell, tb.LimitBuy, tb.ExecSell, tb.ExecBuy, tb.Side, tb.PriceE18,
	)
	return tb, nil
}

func applyBaselineFilter(built []SolnBuilt) {
	type entry struct{ score *big.Int }
	baseline := map[string]*big.Int{}

	for i := range built {
		sb := &built[i]
		if sb.PairsLen == 1 {
			k := sb.PairKey[0].String()
			cur, ok := baseline[k]
			if !ok || sb.PairScore[0].Cmp(cur) > 0 {
				baseline[k] = new(big.Int).Set(sb.PairScore[0])
			}
		}
	}

	for i := range built {
		sb := &built[i]
		if sb.PairsLen <= 1 {
			sb.Survives = true
			continue
		}
		ok := true
		for p := 0; p < sb.PairsLen; p++ {
			k := sb.PairKey[p].String()
			b := baseline[k]
			if b == nil {
				b = big.NewInt(0)
			}
			if sb.PairScore[p].Cmp(b) < 0 {
				ok = false
				break
			}
		}
		sb.Survives = ok
	}
}

func greedyWinners(survivors []SolnBuilt, wmax int) []SolnBuilt {
	used := map[string]bool{}
	out := make([]SolnBuilt, 0, wmax)

	for _, sb := range survivors {
		conflict := false
		for p := 0; p < sb.PairsLen; p++ {
			if used[sb.PairKey[p].String()] {
				conflict = true
				break
			}
		}
		if conflict {
			continue
		}
		out = append(out, sb)
		for p := 0; p < sb.PairsLen; p++ {
			used[sb.PairKey[p].String()] = true
		}
		if len(out) == wmax {
			break
		}
	}
	return out
}

func computeBidsetRoot(built []SolnBuilt, r fr.Element) (*big.Int, error) {
	leaves := make([]fr.Element, 1<<comb.TreeDepth)
	zero := fr.Element{}

	for i := range leaves {
		leaves[i] = zero
	}

	for i := 0; i < len(built) && i < comb.NMax; i++ {
		sb := built[i]
		trCommit := computeTradesCommitOffchain(sb, r)
		leaf := mimcFrElems(
			frFromBig(big.NewInt(999001)),
			frFromBig(sb.SolverAddr),
			frFromBig(sb.SolutionID),
			frFromBig(big.NewInt(int64(len(sb.Trades)))),
			trCommit,
		)
		leaves[i] = leaf
	}

	root := merkleRootMiMC(leaves, comb.TreeDepth)
	return frToBig(root), nil
}

func computeTradesCommitOffchain(sb SolnBuilt, r fr.Element) fr.Element {
	var acc fr.Element
	var pow fr.Element
	pow.SetOne()

	var tmp fr.Element

	for t := 0; t < comb.TMax; t++ {
		var (
			f0, f1, f2, f3, f4, f5, f6, f7, f8 fr.Element
		)

		if t < len(sb.Trades) {
			tr := sb.Trades[t]
			f0 = frFromBig(tr.TradeID)
			f1 = frFromBig(tr.SellToken)
			f2 = frFromBig(tr.BuyToken)
			f3 = frFromBig(tr.LimitSell)
			f4 = frFromBig(tr.LimitBuy)
			f5 = frFromBig(tr.ExecSell)
			f6 = frFromBig(tr.ExecBuy)
			f7 = frFromBig(big.NewInt(int64(tr.Side)))
			f8 = frFromBig(tr.PriceE18)
		} else {
			// inactive => zeros
			f0, f1, f2, f3, f4, f5, f6, f7, f8 =
				fr.Element{}, fr.Element{}, fr.Element{}, fr.Element{}, fr.Element{},
				fr.Element{}, fr.Element{}, fr.Element{}, fr.Element{}
		}

		// acc += f * pow; pow *= r  (fixed order)
		tmp.Mul(&f0, &pow)
		acc.Add(&acc, &tmp)
		pow.Mul(&pow, &r)

		tmp.Mul(&f1, &pow)
		acc.Add(&acc, &tmp)
		pow.Mul(&pow, &r)

		tmp.Mul(&f2, &pow)
		acc.Add(&acc, &tmp)
		pow.Mul(&pow, &r)

		tmp.Mul(&f3, &pow)
		acc.Add(&acc, &tmp)
		pow.Mul(&pow, &r)

		tmp.Mul(&f4, &pow)
		acc.Add(&acc, &tmp)
		pow.Mul(&pow, &r)

		tmp.Mul(&f5, &pow)
		acc.Add(&acc, &tmp)
		pow.Mul(&pow, &r)

		tmp.Mul(&f6, &pow)
		acc.Add(&acc, &tmp)
		pow.Mul(&pow, &r)

		tmp.Mul(&f7, &pow)
		acc.Add(&acc, &tmp)
		pow.Mul(&pow, &r)

		tmp.Mul(&f8, &pow)
		acc.Add(&acc, &tmp)
		pow.Mul(&pow, &r)
	}

	return acc
}

func merkleRootMiMC(leaves []fr.Element, depth int) fr.Element {
	nodes := make([]fr.Element, len(leaves))
	copy(nodes, leaves)
	for level := 0; level < depth; level++ {
		next := make([]fr.Element, len(nodes)/2)
		for i := 0; i < len(next); i++ {
			next[i] = mimcFrElems(nodes[2*i], nodes[2*i+1])
		}
		nodes = next
	}
	return nodes[0]
}

func mimcFrElems(elems ...fr.Element) fr.Element {
	h := frmimc.NewMiMC()
	for _, e := range elems {
		b := e.Marshal()
		h.Write(b)
	}
	sum := h.Sum(nil)
	var out fr.Element
	_ = out.SetBytes(sum)
	return out
}

var oneE18 = big.NewInt(1_000_000_000_000_000_000)

func computeScoreNativeGo(limitSell, limitBuy, execSell, execBuy *big.Int, side int, priceE18 *big.Int) *big.Int {
	if limitSell.Sign() == 0 || limitBuy.Sign() == 0 {
		return big.NewInt(0)
	}

	if side == 0 {
		num := new(big.Int).Mul(limitBuy, execSell)
		partial := divCeilBig(num, limitSell)

		surplusBuy := new(big.Int).Sub(execBuy, partial)
		if surplusBuy.Sign() <= 0 {
			return big.NewInt(0)
		}
		// floor(surplusBuy * price / 1e18)
		num2 := new(big.Int).Mul(surplusBuy, priceE18)
		return new(big.Int).Div(num2, oneE18)
	}

	// buy
	// partialLimitSell = floor(limitSell * execBuy / limitBuy)
	num := new(big.Int).Mul(limitSell, execBuy)
	partialSell := new(big.Int).Div(num, limitBuy)

	surplusSell := new(big.Int).Sub(partialSell, execSell)
	if surplusSell.Sign() <= 0 {
		return big.NewInt(0)
	}
	// surplusBuyEquiv = floor(surplusSell * limitBuy / limitSell)
	num2 := new(big.Int).Mul(surplusSell, limitBuy)
	surplusBuyEq := new(big.Int).Div(num2, limitSell)

	num3 := new(big.Int).Mul(surplusBuyEq, priceE18)
	return new(big.Int).Div(num3, oneE18)
}

func divCeilBig(a, b *big.Int) *big.Int {
	// ceil(a/b) = (a + b - 1) / b
	if b.Sign() == 0 {
		return big.NewInt(0)
	}
	tmp := new(big.Int).Sub(b, big.NewInt(1))
	num := new(big.Int).Add(a, tmp)
	return new(big.Int).Div(num, b)
}

func solidityProofJSON(proof groth16.Proof, pubW witness.Witness) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := proof.WriteRawTo(&buf); err != nil {
		return nil, fmt.Errorf("proof.WriteRawTo: %w", err)
	}
	pb := buf.Bytes()

	const fpSize = 32
	// A=64, B=128, C=64 = 256 bytes
	if len(pb) < 256+4 {
		return nil, fmt.Errorf("raw proof too small: %d", len(pb))
	}

	toBI := func(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

	off := 0
	a0 := toBI(pb[off : off+fpSize])
	off += fpSize
	a1 := toBI(pb[off : off+fpSize])
	off += fpSize
	b00 := toBI(pb[off : off+fpSize])
	off += fpSize
	b01 := toBI(pb[off : off+fpSize])
	off += fpSize
	b10 := toBI(pb[off : off+fpSize])
	off += fpSize
	b11 := toBI(pb[off : off+fpSize])
	off += fpSize
	c0 := toBI(pb[off : off+fpSize])
	off += fpSize
	c1 := toBI(pb[off : off+fpSize])
	off += fpSize

	// commitments: uint32 count then count*64 bytes
	nCommit := int(binary.BigEndian.Uint32(pb[off : off+4]))
	off += 4
	commitments := make([]*big.Int, 0, nCommit*2)
	for i := 0; i < nCommit; i++ {
		commitments = append(commitments, toBI(pb[off:off+fpSize]))
		off += fpSize
		commitments = append(commitments, toBI(pb[off:off+fpSize]))
		off += fpSize
	}
	// If circuit has no committed witnesses, nCommit==0; pad with identity (0,0)
	if nCommit == 0 {
		commitments = []*big.Int{big.NewInt(0), big.NewInt(0)}
	}

	// commitmentPok: G1 (64 bytes)
	var pokX, pokY *big.Int
	if off+2*fpSize <= len(pb) {
		pokX = toBI(pb[off : off+fpSize])
		off += fpSize
		pokY = toBI(pb[off : off+fpSize])
	} else {
		pokX, pokY = big.NewInt(0), big.NewInt(0)
	}

	pubVec, err := witnessToBigints(pubW)
	if err != nil {
		return nil, err
	}

	type out struct {
		Proof         []*big.Int `json:"proof"`         // [A0,A1,B00,B01,B10,B11,C0,C1]
		Commitments   []*big.Int `json:"commitments"`   // [C0x,C0y] (first commitment)
		CommitmentPok []*big.Int `json:"commitmentPok"` // [Px,Py]
		Input         []*big.Int `json:"input"`
	}
	o := out{
		Proof:         []*big.Int{a0, a1, b00, b01, b10, b11, c0, c1},
		Commitments:   commitments[:2], // contract expects uint256[2]
		CommitmentPok: []*big.Int{pokX, pokY},
		Input:         pubVec,
	}
	return json.MarshalIndent(o, "", "  ")
}

func witnessToBigints(w witness.Witness) ([]*big.Int, error) {
	v, ok := w.Vector().(fr.Vector)
	if !ok {
		return nil, fmt.Errorf("unexpected witness vector type: %T", w.Vector())
	}
	out := make([]*big.Int, len(v))
	for i := range v {
		out[i] = frToBig(v[i])
	}
	return out, nil
}

func publicInputsBigints(asn *comb.Circuit) ([]*big.Int, error) {
	w, err := frontend.NewWitness(asn, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return nil, err
	}
	return witnessToBigints(w)
}

func mustDecToBig(s string) *big.Int {
	z, ok := new(big.Int).SetString(s, 10)
	if !ok {
		log.Fatalf("bad decimal: %q", s)
	}
	return z
}

func mustAddrToBig(hexAddr string) *big.Int {
	h := strings.TrimPrefix(strings.ToLower(hexAddr), "0x")
	b, err := hex.DecodeString(h)
	if err != nil {
		log.Fatalf("bad hex address %q: %v", hexAddr, err)
	}
	return new(big.Int).SetBytes(b) // 160-bit fits fine
}

func frFromBig(bi *big.Int) fr.Element {
	var e fr.Element
	e.SetBigInt(bi)
	return e
}

func frToBig(e fr.Element) *big.Int {
	return e.BigInt(new(big.Int))
}

func frAdd(a, b fr.Element) fr.Element {
	var z fr.Element
	z.Add(&a, &b)
	return z
}

func frMul(a, b fr.Element) fr.Element {
	var z fr.Element
	z.Mul(&a, &b)
	return z
}

// trade ID = keccak(uidBytes) mod Fr
func frFromKeccakHex(uidHex string) fr.Element {
	hx := strings.TrimPrefix(uidHex, "0x")
	raw, err := hex.DecodeString(hx)
	if err != nil {
		// fallback: hash string bytes if not hex
		raw = []byte(uidHex)
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(raw)
	d := h.Sum(nil)
	r := fr.Modulus()
	bi := new(big.Int).SetBytes(d)
	bi.Mod(bi, r)
	return frFromBig(bi)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func repoPath(rel string) string {
	_, thisFile, _, _ := runtime.Caller(0)
	base := filepath.Dir(thisFile)
	return filepath.Clean(filepath.Join(base, rel))
}
