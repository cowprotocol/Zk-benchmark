package comb_gnark

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/rangecheck"
)

const (
	NMax       = 120 // Max number of solutions
	TMax       = 10  // Max number of trades per solution
	WMax       = 30  // Max number of winners
	TreeDepth  = 7   // must satisfy 2^TreeDepth >= NMax
	AMT_BITS   = 128 // Bit width for token amounts
	PRICE_BITS = 96  // Bit width for native price
	PairMax    = 10
)

var ONE_E18 = big.NewInt(1_000_000_000_000_000_000)

type Comparators struct {
	LenSol  *cmp.BoundedComparator // for SolutionsLen and i < SolutionsLen
	LenTr   *cmp.BoundedComparator // for TradesLen and t < TradesLen
	LenWin  *cmp.BoundedComparator // for WinnersLen, winCount
	LenPair *cmp.BoundedComparator // for PairsLen and idx < PairsLen

	Score *cmp.BoundedComparator // for score ordering (cap < 2^128-ish)
	U64   *cmp.BoundedComparator // for solution_id ordering
	Amt   *cmp.BoundedComparator
}

func newComparators(api frontend.API) Comparators {
	lenSol := cmp.NewBoundedComparator(api, pow2(9), true)
	lenTr := cmp.NewBoundedComparator(api, pow2(8), true)   // up to 150
	lenWin := cmp.NewBoundedComparator(api, pow2(7), true)  // up to 60
	lenPair := cmp.NewBoundedComparator(api, pow2(6), true) // up to 20

	score := cmp.NewBoundedComparator(api, pow2(128), true)
	u64c := cmp.NewBoundedComparator(api, pow2(64), true)

	amt := cmp.NewBoundedComparator(api, pow2(AMT_BITS+1), true)

	return Comparators{
		LenSol:  lenSol,
		LenTr:   lenTr,
		LenWin:  lenWin,
		LenPair: lenPair,

		Score: score,
		U64:   u64c,
		Amt:   amt,
	}
}

// Can be range-checked to 160 bits (only for safety).
type Address struct {
	Value frontend.Variable
}

type U64 struct {
	Value frontend.Variable
}

type Trade struct {
	// hash(uid bytes) outside and provided as field element
	ID frontend.Variable

	SellToken Address
	BuyToken  Address

	SellAmount   frontend.Variable
	BuyAmount    frontend.Variable
	ExecutedSell frontend.Variable
	ExecutedBuy  frontend.Variable
	Side         frontend.Variable // 0 = Sell, 1 = Buy (enforced boolean)

	NativePriceBuy frontend.Variable
}

type Solution struct {
	SolutionID U64
	Solver     Address

	Trades [TMax]Trade
	// How many trades are actually used (<=TMax). Enforced with selectors.
	TradesLen frontend.Variable

	// pairs_scores: Vec<(DirectedPair, u128)>
	PairsLen     frontend.Variable
	PairKey      [PairMax]frontend.Variable // directed pair key for each bucket (sell + rPair*buy)
	PairScore    [PairMax]frontend.Variable // aggregated score per bucket
	TradePairIdx [TMax]frontend.Variable    // which bucket each trade belongs to
}

// Winner entry (required on-chain).
type Winner struct {
	SolutionID frontend.Variable
	Solver     frontend.Variable
	Score      frontend.Variable
	// TradeID frontend.Variable
}

type Packed struct {
	SolutionID frontend.Variable
	Solver     frontend.Variable
	Score      frontend.Variable
	Commit     frontend.Variable
	PairsLen   frontend.Variable
	PairKey    [PairMax]frontend.Variable
	PairScore  [PairMax]frontend.Variable
}

type Circuit struct {
	// Public
	AuctionID  frontend.Variable `gnark:",public"`
	BidsetRoot frontend.Variable `gnark:",public"`

	WinnersLen frontend.Variable `gnark:",public"`
	Winners    [WMax]Winner      `gnark:",public"`

	// Private
	SolutionsLen frontend.Variable
	Solutions    [NMax]Solution
}

func init() {
	solver.RegisterHint(IsLessHint, DivModHint)
}

func (c *Circuit) Define(api frontend.API) error {
	// Basic bounds
	cmps := newComparators(api)
	rc := rangecheck.New(api)

	assertLeqConst(api, cmps.LenSol, c.SolutionsLen, NMax)
	assertLeqConst(api, cmps.LenWin, c.WinnersLen, WMax)

	// we enforce solutions are provided sorted by SolutionID (ascending) among active solutions.
	for i := 0; i+1 < NMax; i++ {
		both := api.Mul(
			isLessThanConst(api, cmps.LenSol, i, c.SolutionsLen),
			isLessThanConst(api, cmps.LenSol, i+1, c.SolutionsLen),
		)
		assertLtIf(api, cmps.U64, c.Solutions[i].SolutionID.Value, c.Solutions[i+1].SolutionID.Value, both)
	}

	// Compute per-solution:
	// enforce tradesLen bound
	// enforce pair aggregation & assignment (guest pairs_scores)
	// compute score from trades (guest trade_score)
	// compute leaf hash (solution commit)
	leaves := make([]frontend.Variable, 1<<TreeDepth) // padded to power-of-two
	commits := make([]frontend.Variable, NMax)
	totalScores := make([]frontend.Variable, NMax)

	// derive global challenge r from public inputs
	r := deriveChallengeR(api, c.AuctionID)
	rPair := derivePairChallenge(api, c.AuctionID)

	for i := 0; i < (1 << TreeDepth); i++ {
		if i < NMax {
			// activeSolution := (i < SolutionsLen)
			active := isLessThanConst(api, cmps.LenSol, i, c.SolutionsLen)

			// enforce tradesLen <= TMax if active
			assertLeqConstIf(api, cmps.LenTr, c.Solutions[i].TradesLen, TMax, active)
			// enforce pairsLen <= PairMax if active
			assertLeqConstIf(api, cmps.LenPair, c.Solutions[i].PairsLen, PairMax, active)

			//enforce bucket keys are unique among active pair slots
			enforceUniquePairKeys(api, cmps, &c.Solutions[i], active)

			// polynomial accumulator commitment to trades
			tradesCommit := computeTradesCommit(api, cmps, &c.Solutions[i], active, r)

			// score + pair aggregation binding in one pass (no double-scoring)
			alpha := deriveAlpha(api, c.AuctionID, c.Solutions[i].Solver.Value, c.Solutions[i].SolutionID.Value)
			sc, lhsAlpha := computeSolutionScore(api, cmps, rc, &c.Solutions[i], active, alpha, rPair)
			totalScores[i] = sc

			// bind PairScore[] to trades via RHS alpha identity (no scoring here)
			enforcePairAggregationRHS(api, cmps, rc, &c.Solutions[i], active, alpha, lhsAlpha)

			// leaf commitment (binds dataset; does NOT include score)
			leaf := hashSolutionLeaf(api, &c.Solutions[i], tradesCommit, active)
			commits[i] = leaf

			// If not active, leaf must be a fixed pad leaf (0)
			leaves[i] = api.Select(active, leaf, 0)
		} else {
			leaves[i] = 0
		}
	}

	// Rebuild Merkle root from leaves
	root := merkleRootMimc(api, leaves, TreeDepth)

	// Enforce bidset_root matches
	api.AssertIsEqual(root, c.BidsetRoot)

	// baseline filter
	// baseline[pairKey] = max score among single-pair solutions for that pair
	baseKey := make([]frontend.Variable, NMax)
	baseScore := make([]frontend.Variable, NMax)
	baseUsed := make([]frontend.Variable, NMax)
	for j := 0; j < NMax; j++ {
		baseKey[j] = 0
		baseScore[j] = 0
		baseUsed[j] = 0
	}

	for i := 0; i < NMax; i++ {
		active := isLessThanConst(api, cmps.LenSol, i, c.SolutionsLen)

		// isSingle := (PairsLen == 1)
		isSingle := api.IsZero(api.Sub(c.Solutions[i].PairsLen, 1))
		use := api.Mul(active, isSingle)

		// baseline_update(pairKey, pairScore) for single-pair solutions
		key := c.Solutions[i].PairKey[0]
		sc := c.Solutions[i].PairScore[0]
		baselineUpdate(api, cmps, rc, baseKey, baseScore, baseUsed, key, sc, use)
	}

	// survives[i] = 1 if:
	// single-pair (always survive)
	// or multi-pair and for every pair bucket: PairScore >= baselineGet(pairKey)
	survives := make([]frontend.Variable, NMax)
	alive := make([]frontend.Variable, NMax)

	for i := 0; i < NMax; i++ {
		active := isLessThanConst(api, cmps.LenSol, i, c.SolutionsLen)

		isSingle := api.IsZero(api.Sub(c.Solutions[i].PairsLen, 1))
		isMulti := api.Sub(1, isSingle)

		passMulti := frontend.Variable(1)
		for p := 0; p < PairMax; p++ {
			pa := api.Mul(active, isLessThanConst(api, cmps.LenPair, p, c.Solutions[i].PairsLen))
			key := c.Solutions[i].PairKey[p]
			sc := c.Solutions[i].PairScore[p]
			b := baselineGet(api, baseKey, baseScore, baseUsed, key)

			cond := api.Mul(pa, isMulti) // check applies only for active buckets of multi-pair sols

			lt := cmps.Score.IsLess(sc, b) // 1 if sc < b
			ok := api.Sub(1, lt)           // 1 if sc >= b

			// term = (cond==0) ? 1 : ok
			term := api.Add(api.Sub(1, cond), api.Mul(cond, ok))
			passMulti = api.Mul(passMulti, term)
		}

		// survive = active * (isSingle OR (isMulti AND passMulti))
		survive := api.Add(isSingle, api.Mul(isMulti, passMulti))
		survives[i] = api.Mul(active, survive)
		alive[i] = survives[i]
		assertBoolIf(api, alive[i], 1)
	}

	var packed [NMax]Packed

	for s := 0; s < NMax; s++ {
		packed[s].SolutionID = 0
		packed[s].Solver = 0
		packed[s].Score = 0
		packed[s].Commit = 0
		packed[s].PairsLen = 0
		for p := 0; p < PairMax; p++ {
			packed[s].PairKey[p] = 0
			packed[s].PairScore[p] = 0
		}
	}

	// rank[i] = number of alive items before i
	rank := make([]frontend.Variable, NMax)
	pref := frontend.Variable(0)
	for i := 0; i < NMax; i++ {
		rank[i] = pref
		pref = api.Add(pref, alive[i])
	}
	aliveLen := pref // number of survivors

	// packed[rank[i]] = original[i] when alive[i]==1
	for i := 0; i < NMax; i++ {
		for sIdx := 0; sIdx < NMax; sIdx++ {
			isSlot := api.IsZero(api.Sub(rank[i], sIdx))
			write := api.Mul(alive[i], isSlot)

			packed[sIdx].SolutionID = api.Select(write, c.Solutions[i].SolutionID.Value, packed[sIdx].SolutionID)
			packed[sIdx].Solver = api.Select(write, c.Solutions[i].Solver.Value, packed[sIdx].Solver)
			packed[sIdx].Score = api.Select(write, totalScores[i], packed[sIdx].Score)
			packed[sIdx].Commit = api.Select(write, commits[i], packed[sIdx].Commit)
			packed[sIdx].PairsLen = api.Select(write, c.Solutions[i].PairsLen, packed[sIdx].PairsLen)

			for p := 0; p < PairMax; p++ {
				packed[sIdx].PairKey[p] = api.Select(write, c.Solutions[i].PairKey[p], packed[sIdx].PairKey[p])
				packed[sIdx].PairScore[p] = api.Select(write, c.Solutions[i].PairScore[p], packed[sIdx].PairScore[p])
			}
		}
	}

	for i := 0; i+1 < NMax; i++ {
		both := api.Mul(
			isLessThanConst(api, cmps.LenSol, i, aliveLen),
			isLessThanConst(api, cmps.LenSol, i+1, aliveLen),
		)

		// score[i] >= score[i+1]
		assertGeqIf(api, cmps.Score, packed[i].Score, packed[i+1].Score, both)

		// if scores equal: commit[i] >= commit[i+1] (desc)
		eqScore := api.IsZero(api.Sub(packed[i].Score, packed[i+1].Score))
		cond := api.Mul(both, eqScore)
		ltCommit := hintIsLessStrict(api, rc, packed[i].Commit, packed[i+1].Commit, 254, cond)
		api.AssertIsEqual(api.Mul(cond, ltCommit), 0)
	}

	// Greedy select winners with disjoint directed pairs across solutions
	computed := greedySelectWinners(api, cmps, packed, aliveLen)

	// Compare computed winners to public Winners (up to WinnersLen)
	for w := 0; w < WMax; w++ {
		activeW := isLessThanConst(api, cmps.LenWin, w, c.WinnersLen)
		api.AssertIsEqual(api.Mul(activeW, api.Sub(computed[w].SolutionID, c.Winners[w].SolutionID)), 0)
		api.AssertIsEqual(api.Mul(activeW, api.Sub(computed[w].Solver, c.Winners[w].Solver)), 0)
		api.AssertIsEqual(api.Mul(activeW, api.Sub(computed[w].Score, c.Winners[w].Score)), 0)

	}

	return nil
}

func hashSolutionLeaf(
	api frontend.API,
	s *Solution,
	tradesHash, active frontend.Variable,
) frontend.Variable {
	h, _ := mimc.NewMiMC(api)
	h.Write(999001, s.Solver.Value, s.SolutionID.Value, s.TradesLen, tradesHash)
	return api.Select(active, h.Sum(), 0)
}

// ideally it should also have some randomness after bidset_root is fixed to prevent malleability when solver chooses the witnesses.
func deriveChallengeR(api frontend.API, auctionID frontend.Variable) frontend.Variable {
	h, _ := mimc.NewMiMC(api)
	h.Write(auctionID, 0xA11CE001)
	r := h.Sum()
	return r
}

func merkleRootMimc(api frontend.API, leaves []frontend.Variable, depth int) frontend.Variable {
	nodes := make([]frontend.Variable, len(leaves))
	copy(nodes, leaves)

	for level := 0; level < depth; level++ {
		next := make([]frontend.Variable, len(nodes)/2)
		for i := 0; i < len(next); i++ {
			h, _ := mimc.NewMiMC(api)
			h.Write(nodes[2*i], nodes[2*i+1])
			next[i] = h.Sum()
		}
		nodes = next
	}
	return nodes[0]
}

func computeTradesCommit(api frontend.API, cmps Comparators, s *Solution, active, r frontend.Variable) frontend.Variable {
	acc := frontend.Variable(0)
	pow := frontend.Variable(1)

	for t := 0; t < TMax; t++ {
		ta := api.Mul(active, isLessThanConst(api, cmps.LenTr, t, s.TradesLen))
		tr := s.Trades[t]

		// gated fields (0 when trade inactive)
		f0 := api.Select(ta, tr.ID, 0)
		f1 := api.Select(ta, tr.SellToken.Value, 0)
		f2 := api.Select(ta, tr.BuyToken.Value, 0)
		f3 := api.Select(ta, tr.SellAmount, 0)
		f4 := api.Select(ta, tr.BuyAmount, 0)
		f5 := api.Select(ta, tr.ExecutedSell, 0)
		f6 := api.Select(ta, tr.ExecutedBuy, 0)
		f7 := api.Select(ta, tr.Side, 0)
		f8 := api.Select(ta, tr.NativePriceBuy, 0)

		// acc += f_k * pow && pow *= r  (fixed order)
		acc = api.Add(acc, api.Mul(f0, pow))
		pow = api.Mul(pow, r)
		acc = api.Add(acc, api.Mul(f1, pow))
		pow = api.Mul(pow, r)
		acc = api.Add(acc, api.Mul(f2, pow))
		pow = api.Mul(pow, r)
		acc = api.Add(acc, api.Mul(f3, pow))
		pow = api.Mul(pow, r)
		acc = api.Add(acc, api.Mul(f4, pow))
		pow = api.Mul(pow, r)
		acc = api.Add(acc, api.Mul(f5, pow))
		pow = api.Mul(pow, r)
		acc = api.Add(acc, api.Mul(f6, pow))
		pow = api.Mul(pow, r)
		acc = api.Add(acc, api.Mul(f7, pow))
		pow = api.Mul(pow, r)
		acc = api.Add(acc, api.Mul(f8, pow))
		pow = api.Mul(pow, r)
	}

	return api.Select(active, acc, 0)
}

func derivePairChallenge(api frontend.API, auctionID frontend.Variable) frontend.Variable {
	h, _ := mimc.NewMiMC(api)
	// domain separator so it's not the same as the trades-commit challenge
	h.Write(auctionID, 0xA11CE002)
	return h.Sum()
}

func deriveAlpha(api frontend.API, auctionID, solver, solutionID frontend.Variable) frontend.Variable {
	h, _ := mimc.NewMiMC(api)
	// domain separator distinct from r/rPair
	h.Write(auctionID, 0xA11CE003, solver, solutionID)
	return h.Sum()
}

func computeSolutionScore(
	api frontend.API,
	cmps Comparators,
	rc frontend.Rangechecker,
	s *Solution,
	active frontend.Variable,
	alpha frontend.Variable,
	rPair frontend.Variable,
) (total frontend.Variable, lhsAlpha frontend.Variable) {
	total = frontend.Variable(0)
	lhsAlpha = frontend.Variable(0)

	// precompute alpha^k for k in [0..PairMax-1]
	alphaPow := make([]frontend.Variable, PairMax)
	alphaPow[0] = 1
	for k := 1; k < PairMax; k++ {
		alphaPow[k] = api.Mul(alphaPow[k-1], alpha)
	}

	for t := 0; t < TMax; t++ {
		ta := api.Mul(active, isLessThanConst(api, cmps.LenTr, t, s.TradesLen))
		tr := s.Trades[t]

		// Ensure inactive trade fields are 0-ish (so unconditional range checks are safe)
		api.AssertIsEqual(api.Mul(api.Sub(1, ta), tr.SellAmount), 0)
		api.AssertIsEqual(api.Mul(api.Sub(1, ta), tr.BuyAmount), 0)
		api.AssertIsEqual(api.Mul(api.Sub(1, ta), tr.ExecutedSell), 0)
		api.AssertIsEqual(api.Mul(api.Sub(1, ta), tr.ExecutedBuy), 0)
		api.AssertIsEqual(api.Mul(api.Sub(1, ta), tr.NativePriceBuy), 0)
		api.AssertIsEqual(api.Mul(api.Sub(1, ta), tr.Side), 0)

		// side boolean
		assertBoolIf(api, tr.Side, ta)

		pi := s.TradePairIdx[t]
		piOK := cmps.LenPair.IsLess(pi, s.PairsLen)
		api.AssertIsEqual(api.Mul(ta, api.Sub(1, piOK)), 0)

		// expectedKey = sell + rPair*buy
		expKey := api.Add(tr.SellToken.Value, api.Mul(rPair, tr.BuyToken.Value))
		enforceKeyMatchBySelector(api, s.PairKey[:], pi, expKey, ta)

		// Guard divisors against 0 for inactive trades
		safeLimSell := api.Select(ta, tr.SellAmount, 1)
		safeLimBuy := api.Select(ta, tr.BuyAmount, 1)

		// Sell side:
		// partial_limit_buy = ceil(limit_buy * executed_sell / limit_sell)
		// score_native = floor((executed_buy - partial_limit_buy) * native_price_buy / 1e18) if executed_buy > partial_limit_buy
		//
		// Buy side:
		// partial_limit_sell = floor(limit_sell * executed_buy / limit_buy)
		// surplus_sell = partial_limit_sell - executed_sell  if partial_limit_sell > executed_sell
		// surplus_buy_equiv = floor(surplus_sell * limit_buy / limit_sell)
		// score_native = floor(surplus_buy_equiv * native_price_buy / 1e18)

		limBuy_mul_exSell := api.Mul(tr.BuyAmount, tr.ExecutedSell)
		limSell_mul_exBuy := api.Mul(tr.SellAmount, tr.ExecutedBuy)

		partialLimitBuy := divCeil(api, rc, limBuy_mul_exSell, safeLimSell, AMT_BITS*2+1, AMT_BITS, AMT_BITS+1)
		partialLimitSell := divFloor(api, rc, limSell_mul_exBuy, safeLimBuy, AMT_BITS*2, AMT_BITS, AMT_BITS+1)

		sellPos := hintIsLessStrict(api, rc, partialLimitBuy, tr.ExecutedBuy, AMT_BITS+2, ta)  // 1 iff execBuy > partial
		buyPos := hintIsLessStrict(api, rc, tr.ExecutedSell, partialLimitSell, AMT_BITS+2, ta) // 1 iff partial > execSell

		// Sell: executed_buy > partialLimitBuy
		// Buy:  partialLimitSell > executed_sell
		sellCond := api.Mul(ta, api.Sub(1, tr.Side))
		buyCond := api.Mul(ta, tr.Side)

		rawSurplusBuySell := api.Sub(tr.ExecutedBuy, partialLimitBuy) // may be 0 or wrap
		rawSurplusSellBuy := api.Sub(partialLimitSell, tr.ExecutedSell)

		surplusBuySell := api.Mul(rawSurplusBuySell, api.Mul(sellCond, sellPos)) // only nonzero for active sell trades with execBuy > partial
		surplusSellBuy := api.Mul(rawSurplusSellBuy, api.Mul(buyCond, buyPos))

		// Buy side conversion: surplusBuyEquiv = floor(surplusSell * limitBuy / limitSell)
		// When buyPos=0, surplusSellBuy=0 so this is forced to 0 cleanly.
		surplusSell_mul_limBuy := api.Mul(surplusSellBuy, tr.BuyAmount)
		surplusBuyEquiv := divFloor(api, rc, surplusSell_mul_limBuy, safeLimSell, AMT_BITS*2+1, AMT_BITS, AMT_BITS+1)

		// ensure surplusBuyEquiv is 0 unless (active buy trade AND buyPos)
		surplusBuyEquiv = api.Mul(surplusBuyEquiv, api.Mul(buyCond, buyPos))

		surplusInBuyToken := api.Add(surplusBuySell, surplusBuyEquiv)

		surplus_mul_price := api.Mul(surplusInBuyToken, tr.NativePriceBuy)
		scoreNative := divFloor(api, rc, surplus_mul_price, frontend.Variable(ONE_E18), AMT_BITS*2+PRICE_BITS, 64, AMT_BITS+PRICE_BITS)

		scoreT := api.Mul(ta, scoreNative)
		total = api.Add(total, scoreT)

		// lhsAlpha += scoreT * alpha^{pairIdx}
		alphaAt := selectFromSmallArray(api, alphaPow, pi)
		lhsAlpha = api.Add(lhsAlpha, api.Mul(scoreT, alphaAt))
	}

	return api.Select(active, total, 0), api.Select(active, lhsAlpha, 0)
}

func enforcePairAggregationRHS(
	api frontend.API,
	cmps Comparators,
	rc frontend.Rangechecker,
	s *Solution,
	active frontend.Variable,
	alpha frontend.Variable,
	lhsAlpha frontend.Variable,
) {
	// precompute alpha^k
	alphaPow := make([]frontend.Variable, PairMax)
	alphaPow[0] = 1
	for k := 1; k < PairMax; k++ {
		alphaPow[k] = api.Mul(alphaPow[k-1], alpha)
	}

	rhs := frontend.Variable(0)
	for k := 0; k < PairMax; k++ {
		ka := api.Mul(active, isLessThanConst(api, cmps.LenPair, k, s.PairsLen))
		rhs = api.Add(rhs, api.Mul(ka, api.Mul(s.PairScore[k], alphaPow[k])))

		// enforce PairScore is a u128 when used
		rc.Check(api.Select(ka, s.PairScore[k], 0), 128)

		// enforce unused pair slots are zero (prevents hiding junk)
		api.AssertIsEqual(api.Mul(api.Sub(1, ka), s.PairKey[k]), 0)
		api.AssertIsEqual(api.Mul(api.Sub(1, ka), s.PairScore[k]), 0)
	}

	api.AssertIsEqual(api.Mul(active, api.Sub(lhsAlpha, rhs)), 0)
}

// enforce PairKey[idx] == expKey under cond, without indexing
func enforceKeyMatchBySelector(api frontend.API, keys []frontend.Variable, idx, expKey, cond frontend.Variable) {
	// For each k: if idx==k and cond==1, then keys[k] == expKey.
	for k := 0; k < len(keys); k++ {
		isK := api.IsZero(api.Sub(idx, k))
		enf := api.Mul(cond, isK)
		api.AssertIsEqual(api.Mul(enf, api.Sub(keys[k], expKey)), 0)
	}
}

// selectFromSmallArray returns arr[idx] (idx is assumed < len(arr))
func selectFromSmallArray(api frontend.API, arr []frontend.Variable, idx frontend.Variable) frontend.Variable {
	out := frontend.Variable(0)
	for k := 0; k < len(arr); k++ {
		isK := api.IsZero(api.Sub(idx, k))
		out = api.Add(out, api.Mul(isK, arr[k]))
	}
	return out
}

func enforceUniquePairKeys(api frontend.API, cmps Comparators, s *Solution, active frontend.Variable) {
	for i := 0; i < PairMax; i++ {
		ai := api.Mul(active, isLessThanConst(api, cmps.LenPair, i, s.PairsLen))
		for j := i + 1; j < PairMax; j++ {
			aj := api.Mul(active, isLessThanConst(api, cmps.LenPair, j, s.PairsLen))
			cond := api.Mul(ai, aj)

			eq := api.IsZero(api.Sub(s.PairKey[i], s.PairKey[j]))
			// if both active, keys must NOT be equal
			api.AssertIsEqual(api.Mul(cond, eq), 0)
		}
	}
}

func baselineGet(
	api frontend.API,
	baseKey, baseScore, baseUsed []frontend.Variable,
	key frontend.Variable,
) frontend.Variable {
	out := frontend.Variable(0)
	for j := 0; j < len(baseKey); j++ {
		eq := api.IsZero(api.Sub(key, baseKey[j]))
		out = api.Add(out, api.Mul(api.Mul(baseUsed[j], eq), baseScore[j]))
	}
	return out
}

func baselineUpdate(
	api frontend.API,
	cmps Comparators,
	rc frontend.Rangechecker,
	baseKey, baseScore, baseUsed []frontend.Variable,
	key, sc, use frontend.Variable,
) {
	// found = OR_j (baseUsed[j]==1 && baseKey[j]==key)
	found := frontend.Variable(0)
	for j := 0; j < len(baseKey); j++ {
		eq := api.IsZero(api.Sub(key, baseKey[j]))
		found = api.Or(found, api.Mul(baseUsed[j], eq))
	}

	// First pass: if found, do max-update on the matching slots
	for j := 0; j < len(baseKey); j++ {
		eq := api.IsZero(api.Sub(key, baseKey[j]))
		doUpd := api.Mul(use, api.Mul(baseUsed[j], eq))

		// lt == 1 iff baseScore[j] < sc (strict)
		lt := hintIsLessStrict(api, rc, baseScore[j], sc, 128, doUpd)
		newScore := api.Select(lt, sc, baseScore[j])
		baseScore[j] = api.Select(doUpd, newScore, baseScore[j])
	}

	// Second pass: if not found, insert into first free slot
	inserted := frontend.Variable(0)
	for j := 0; j < len(baseKey); j++ {
		free := api.Sub(1, baseUsed[j])
		canIns := api.Mul(use, api.Mul(api.Sub(1, found), api.Mul(free, api.Sub(1, inserted))))

		baseKey[j] = api.Select(canIns, key, baseKey[j])
		baseScore[j] = api.Select(canIns, sc, baseScore[j])
		baseUsed[j] = api.Select(canIns, frontend.Variable(1), baseUsed[j])

		inserted = api.Or(inserted, canIns)
	}

	// If use==1, we must have either found or inserted (no overflow)
	ok := api.Or(found, inserted)
	api.AssertIsEqual(api.Mul(use, api.Sub(1, ok)), 0)
}

func greedySelectWinners(
	api frontend.API,
	cmps Comparators,
	packed [NMax]Packed,
	aliveLen frontend.Variable,
) [WMax]Winner {
	var winners [WMax]Winner
	for w := 0; w < WMax; w++ {
		winners[w].SolutionID = frontend.Variable(0)
		winners[w].Solver = frontend.Variable(0)
		winners[w].Score = frontend.Variable(0)
	}

	var usedKey [WMax][PairMax]frontend.Variable
	var usedMask [WMax][PairMax]frontend.Variable
	var usedSlotMask [WMax]frontend.Variable

	for w := 0; w < WMax; w++ {
		usedSlotMask[w] = 0
		for p := 0; p < PairMax; p++ {
			usedKey[w][p] = 0
			usedMask[w][p] = 0
		}
	}

	winCount := frontend.Variable(0)

	for i := 0; i < NMax; i++ {
		activeI := isLessThanConst(api, cmps.LenSol, i, aliveLen)
		hasPairs := api.Sub(1, api.IsZero(packed[i].PairsLen))
		activeI = api.Mul(activeI, hasPairs)

		// precompute candActive[cp]: depends only on (i, cp)
		var candActive [PairMax]frontend.Variable
		for cp := 0; cp < PairMax; cp++ {
			candActive[cp] = api.Mul(activeI, isLessThanConst(api, cmps.LenPair, cp, packed[i].PairsLen))
		}

		// use Add accumulation instead of Or (Add is free in R1CS)
		conflictSum := frontend.Variable(0)
		for w := 0; w < WMax; w++ {
			for p := 0; p < PairMax; p++ {
				usedActive := api.Mul(usedSlotMask[w], usedMask[w][p])
				for cp := 0; cp < PairMax; cp++ {
					eq := api.IsZero(api.Sub(packed[i].PairKey[cp], usedKey[w][p]))
					conflictSum = api.Add(conflictSum, api.Mul(api.Mul(usedActive, candActive[cp]), eq))
				}
			}
		}
		// Single IsZero to convert sum to boolean
		conflict := api.Sub(1, api.IsZero(conflictSum))

		hasSlot := isLessThanVarConst(api, cmps.LenWin, winCount, WMax)
		canPick := api.Mul(activeI, api.Mul(api.Sub(1, conflict), hasSlot))

		// precompute pairActive[p] — depends only on (i, p)
		var pairActive [PairMax]frontend.Variable
		for p := 0; p < PairMax; p++ {
			pairActive[p] = isLessThanConst(api, cmps.LenPair, p, packed[i].PairsLen)
		}

		for w := 0; w < WMax; w++ {
			isThisSlot := api.IsZero(api.Sub(winCount, w))
			write := api.Mul(canPick, isThisSlot)

			winners[w].SolutionID = api.Select(write, packed[i].SolutionID, winners[w].SolutionID)
			winners[w].Solver = api.Select(write, packed[i].Solver, winners[w].Solver)
			winners[w].Score = api.Select(write, packed[i].Score, winners[w].Score)

			usedSlotMask[w] = api.Select(write, frontend.Variable(1), usedSlotMask[w])

			for p := 0; p < PairMax; p++ {
				wrP := api.Mul(write, pairActive[p])
				usedKey[w][p] = api.Select(wrP, packed[i].PairKey[p], usedKey[w][p])
				usedMask[w][p] = api.Select(wrP, frontend.Variable(1), usedMask[w][p])
			}
		}

		winCount = api.Add(winCount, canPick)
	}

	for w := 0; w < WMax; w++ {
		assertBoolIf(api, usedSlotMask[w], 1)
		for p := 0; p < PairMax; p++ {
			assertBoolIf(api, usedMask[w][p], 1)
		}
	}

	return winners
}

func assertBoolIf(api frontend.API, x, cond frontend.Variable) {
	api.AssertIsEqual(api.Mul(cond, api.Mul(x, api.Sub(1, x))), 0)
}

func isLessThanConst(api frontend.API, bc *cmp.BoundedComparator, i int, x frontend.Variable) frontend.Variable {
	return bc.IsLess(frontend.Variable(i), x)
}

func isLessThanVarConst(api frontend.API, bc *cmp.BoundedComparator, x frontend.Variable, c int) frontend.Variable {
	return bc.IsLess(x, frontend.Variable(c))
}

func isLessThanOrEqConst(api frontend.API, bc *cmp.BoundedComparator, x frontend.Variable, c int) frontend.Variable {
	// x <= c  <=> x < c+1
	return bc.IsLess(x, frontend.Variable(c+1))
}

func assertLeqConst(api frontend.API, bc *cmp.BoundedComparator, x frontend.Variable, c int) {
	api.AssertIsEqual(bc.IsLess(x, frontend.Variable(c+1)), 1)
}

func assertLeqConstIf(api frontend.API, bc *cmp.BoundedComparator, x frontend.Variable, c int, cond frontend.Variable) {
	ok := bc.IsLess(x, frontend.Variable(c+1))
	api.AssertIsEqual(api.Mul(cond, api.Sub(1, ok)), 0)
}

func assertLtIf(api frontend.API, bc *cmp.BoundedComparator, a, b, cond frontend.Variable) {
	lt := bc.IsLess(a, b)
	api.AssertIsEqual(api.Mul(cond, api.Sub(1, lt)), 0)
}

func assertGeqIf(api frontend.API, bc *cmp.BoundedComparator, a, b, cond frontend.Variable) {
	lt := bc.IsLess(a, b) // 1 if a < b
	ok := api.Sub(1, lt)  // 1 if a >= b
	api.AssertIsEqual(api.Mul(cond, api.Sub(1, ok)), 0)
}

func pow2(bits int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(bits))
}

func divCeil(api frontend.API, rc frontend.Rangechecker, a, b frontend.Variable, aBits, bBits, qBits int) frontend.Variable {
	// ceil(a/b) = floor((a + b - 1)/b)
	a2 := api.Add(a, api.Sub(b, 1))
	return divFloor(api, rc, a2, b, aBits+1, bBits, qBits)
}

func divFloor(api frontend.API, rc frontend.Rangechecker, a, b frontend.Variable, aBits, bBits, qBits int) frontend.Variable {
	// q,r from hint
	out, err := api.NewHint(DivModHint, 2, a, b)
	if err != nil {
		panic(err)
	}
	q := out[0]
	r := out[1]

	// Range-check q,r
	rc.Check(q, qBits)
	rc.Check(r, bBits) // r < b so it fits in bBits

	// Enforce: a = b*q + r
	api.AssertIsEqual(a, api.Add(api.Mul(b, q), r))

	// Enforcing r < b WITHOUT cmp
	// s = b - 1 - r must be in [0, 2^bBits)
	// If r >= b then s underflows to a huge field element & fails rangecheck.
	s := api.Sub(api.Sub(b, 1), r)
	rc.Check(s, bBits)

	return q
}

// hintIsLessStrict returns 1 if a < b (strict), else 0.
// Circuit verifies the hint via range checks on the difference.
func hintIsLessStrict(
	api frontend.API,
	rc frontend.Rangechecker,
	a, b frontend.Variable,
	bits int,
	cond frontend.Variable,
) frontend.Variable {
	out, err := api.NewHint(IsLessHint, 1, a, b)
	if err != nil {
		panic(err)
	}
	lt := out[0]
	assertBoolIf(api, lt, cond)

	// If lt==1: b - a - 1 >= 0  (meaning b > a)
	// If lt==0: a - b >= 0      (meaning a >= b)
	dPos := api.Sub(api.Sub(b, a), 1) // b-a-1
	dNeg := api.Sub(a, b)             // a-b
	checkVal := api.Select(lt, dPos, dNeg)
	rc.Check(api.Select(cond, checkVal, 0), bits)

	return lt
}

// results[0] = 1 if a < b else 0
func IsLessHint(mod *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 2 || len(results) != 1 {
		return nil
	}
	a := new(big.Int).Set(inputs[0])
	b := new(big.Int).Set(inputs[1])
	if a.Cmp(b) < 0 {
		results[0].SetInt64(1)
	} else {
		results[0].SetInt64(0)
	}
	return nil
}

// results[0] = q = floor(a/b)
// results[1] = r = a - b*q
func DivModHint(mod *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 2 || len(results) != 2 {
		return nil
	}
	a := new(big.Int).Set(inputs[0])
	b := new(big.Int).Set(inputs[1])

	// b == 0 enforced via r<b constraint
	// But guard anyway to avoid panic
	if b.Sign() == 0 {
		results[0].SetInt64(0)
		results[1].SetInt64(0)
		return nil
	}

	q := new(big.Int).Quo(a, b)
	r := new(big.Int).Rem(a, b)

	results[0].Set(q)
	results[1].Set(r)
	return nil
}
