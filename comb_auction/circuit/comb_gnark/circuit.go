package comb_gnark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/rangecheck"
)

const (
	NMax       = 250 // Max number of splitted solutions
	TMax       = 40  // Max number of trades per solution
	WMax       = 80  // Max number of winners
	TreeDepth  = 8   // must satisfy 2^TreeDepth >= NMax
	AMT_BITS   = 64  // Bit width for token amounts
	PRICE_BITS = 64  // Bit width for native price
)

var ONE_E18 = big.NewInt(1_000_000_000_000_000_000)

type Comparators struct {
	LenSol *cmp.BoundedComparator // for SolutionsLen and i < SolutionsLen
	LenTr  *cmp.BoundedComparator // for TradesLen and t < TradesLen
	LenWin *cmp.BoundedComparator // for WinnersLen, winCount, usedLen
	Score  *cmp.BoundedComparator // for score ordering (cap < 2^128)
	Amt    *cmp.BoundedComparator
}

func newComparators(api frontend.API) Comparators {
	lenSol := cmp.NewBoundedComparator(api, pow2(9), true)
	lenTr := cmp.NewBoundedComparator(api, pow2(6), true)
	lenWin := cmp.NewBoundedComparator(api, pow2(7), true)
	score := cmp.NewBoundedComparator(api, pow2(128), true)
	amt := cmp.NewBoundedComparator(api, pow2(AMT_BITS+1), true)

	return Comparators{
		LenSol: lenSol,
		LenTr:  lenTr,
		LenWin: lenWin,
		Score:  score,
		Amt:    amt,
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
}

// Winner entry (required on-chain).
type Winner struct {
	SolutionID frontend.Variable
	Solver     frontend.Variable
	Score      frontend.Variable
	// TradeID frontend.Variable
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

func (c *Circuit) Define(api frontend.API) error {
	// Basic bounds
	cmps := newComparators(api)
	rc := rangecheck.New(api)

	assertLeqConst(api, cmps.LenSol, c.SolutionsLen, NMax)
	assertLeqConst(api, cmps.LenWin, c.WinnersLen, WMax)

	scores := make([]frontend.Variable, NMax)
	pairKeys := make([]frontend.Variable, NMax)

	// Compute per-solution:
	// enforce tradesLen bound
	// enforce all trades share same directed pair
	// compute score from trades
	// compute leaf hash
	leaves := make([]frontend.Variable, 1<<TreeDepth) // padded to power-of-two
	// derive global challenge r from public inputs
	r := deriveChallengeR(api, c.BidsetRoot, c.AuctionID)
	rPair := derivePairChallenge(api, c.BidsetRoot, c.AuctionID)

	for i := 0; i < (1 << TreeDepth); i++ {
		if i < NMax {
			// activeSolution := (i < SolutionsLen)
			active := isLessThanConst(api, cmps.LenSol, i, c.SolutionsLen)

			// enforce tradesLen <= TMax if active
			assertLeqConstIf(api, cmps.LenTr, c.Solutions[i].TradesLen, TMax, active)

			// derive pairKey and enforce consistency if active
			pk := computePairKeyFromTrades(api, cmps, &c.Solutions[i], active, rPair)
			pairKeys[i] = pk

			// compute score if active
			sc := computeSolutionScore(api, cmps, rc, &c.Solutions[i], active)
			scores[i] = sc

			// polynomial accumulator commitment to trades
			tradesCommit := computeTradesCommit(api, cmps, &c.Solutions[i], active, r)

			// leaf commitment
			leaf := hashSolutionLeaf(api, &c.Solutions[i], sc, pk, tradesCommit, active)

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

	// Enforce solutions are sorted by score descending (only among active solutions)
	for i := 0; i+1 < NMax; i++ {
		both := api.Mul(
			isLessThanConst(api, cmps.LenSol, i, c.SolutionsLen),
			isLessThanConst(api, cmps.LenSol, i+1, c.SolutionsLen),
		)
		assertGeqIf(api, cmps.Score, scores[i], scores[i+1], both)
	}

	// Greedy select winners (uniform directed price constraint via pair disjointness)
	computed := greedySelectWinners(api, cmps, c.Solutions[:], c.SolutionsLen, scores, pairKeys)

	// Compare computed winners to public Winners (up to WinnersLen)
	for w := 0; w < WMax; w++ {
		activeW := isLessThanConst(api, cmps.LenWin, w, c.WinnersLen)
		api.AssertIsEqual(api.Select(activeW, computed[w].SolutionID, c.Winners[w].SolutionID), c.Winners[w].SolutionID)
		api.AssertIsEqual(api.Select(activeW, computed[w].Solver, c.Winners[w].Solver), c.Winners[w].Solver)
		api.AssertIsEqual(api.Select(activeW, computed[w].Score, c.Winners[w].Score), c.Winners[w].Score)
	}

	return nil
}

func hashSolutionLeaf(api frontend.API,
	s *Solution,
	computedScore, computedPairKey, tradesHash, active frontend.Variable) frontend.Variable {

	h, _ := mimc.NewMiMC(api)
	h.Write(
		s.Solver.Value,
		s.SolutionID.Value,
		s.TradesLen,
		computedScore,
		computedPairKey,
		tradesHash,
	)
	return api.Select(active, h.Sum(), 0)
}

// ideally it should also have some randomness after bidset_root is fixed to prevent malleability when solver chooses the witnesses.
func deriveChallengeR(api frontend.API, bidsetRoot, auctionID frontend.Variable) frontend.Variable {
	h, _ := mimc.NewMiMC(api)
	h.Write(bidsetRoot, auctionID)
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
		ta := api.Mul(active, isLessThanVarConst(api, cmps.LenTr, s.TradesLen, t+1))
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

func derivePairChallenge(api frontend.API, bidsetRoot, auctionID frontend.Variable) frontend.Variable {
	h, _ := mimc.NewMiMC(api)
	// domain separator so it's not the same as the trades-commit challenge
	h.Write(bidsetRoot, auctionID, 123456789)
	return h.Sum()
}

func computePairKeyFromTrades(api frontend.API, cmps Comparators, s *Solution, active, rPair frontend.Variable) frontend.Variable {
	// Enforce side is boolean for each active trade, and all trades share same (sell,buy).
	// pairKey = mimc(sellToken, buyToken)
	firstSell := s.Trades[0].SellToken.Value
	firstBuy := s.Trades[0].BuyToken.Value

	// range-check tokens as 160-bit addresses
	// rangeCheck160If(api, firstSell, active)

	for t := 0; t < TMax; t++ {
		// tradeActive := (t < tradesLen) && active
		ta := api.Mul(active, isLessThanVarConst(api, cmps.LenTr, s.TradesLen, t+1))

		// side boolean
		assertBoolIf(api, s.Trades[t].Side, ta)

		// enforce same pair for all active trades
		api.AssertIsEqual(
			api.Select(ta, s.Trades[t].SellToken.Value, firstSell),
			s.Trades[t].SellToken.Value,
		)
		api.AssertIsEqual(
			api.Select(ta, s.Trades[t].BuyToken.Value, firstBuy),
			s.Trades[t].BuyToken.Value,
		)
	}

	return api.Add(firstSell, api.Mul(rPair, firstBuy))
}

func computeSolutionScore(api frontend.API, cmps Comparators, rc frontend.Rangechecker, s *Solution, active frontend.Variable) frontend.Variable {
	sum := frontend.Variable(0)

	for t := 0; t < TMax; t++ {
		ta := api.Mul(active, isLessThanVarConst(api, cmps.LenTr, s.TradesLen, t+1))

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

		// TODO: Range checks (good to have for security, optional otherwise)
		// rangeCheckBitsIf(api, tr.SellAmount, AMT_BITS, ta)
		// rangeCheckBitsIf(api, tr.BuyAmount, AMT_BITS, ta)
		// rangeCheckBitsIf(api, tr.ExecutedSell, AMT_BITS, ta)
		// rangeCheckBitsIf(api, tr.ExecutedBuy, AMT_BITS, ta)
		// rangeCheckBitsIf(api, tr.NativePriceBuy, PRICE_BITS, ta)

		// Precompute products
		// Sell: limit_buy = ceil(executed_sell * buy_amount / sell_amount)
		// Buy:  limit_sell = floor(sell_amount * executed_buy / buy_amount)
		exSell_mul_buyAmt := api.Mul(tr.ExecutedSell, tr.BuyAmount)
		sellAmt_mul_exBuy := api.Mul(tr.SellAmount, tr.ExecutedBuy)

		limitBuy := divCeil(
			api,
			rc,
			exSell_mul_buyAmt,
			tr.SellAmount,
			AMT_BITS*2+1,
			AMT_BITS,
			AMT_BITS+1,
		)
		limitSell := divFloor(api, rc, sellAmt_mul_exBuy, tr.BuyAmount, AMT_BITS*2, AMT_BITS, AMT_BITS+1)

		// Surplus:
		// Sell: surplus_buy = executed_buy - limitBuy
		// Buy:  surplus_sell = limitSell - executed_sell
		surplusSellSide := api.Sub(tr.ExecutedBuy, limitBuy)
		surplusBuySide := api.Sub(limitSell, tr.ExecutedSell)

		// Enforce non-negative surplus (otherwise solution invalid)
		sellCond := api.Mul(ta, api.Sub(1, tr.Side)) // side==0
		buyCond := api.Mul(ta, tr.Side)              // side==1
		// When sellCond=1: ExecutedBuy >= limitBuy
		_ = assertGeqIfRange(api, rc, tr.ExecutedBuy, limitBuy, sellCond, AMT_BITS+1)
		// When buyCond=1: limitSell >= ExecutedSell
		_ = assertGeqIfRange(api, rc, limitSell, tr.ExecutedSell, buyCond, AMT_BITS+1)

		// Select surplus in surplus-token
		surplusInSurplusToken := api.Select(tr.Side, surplusBuySide, surplusSellSide) // if side=1 => Buy order surplus in sell token

		// For Buy orders, convert surplus_sell -> buy tokens using order limit ratio:
		// surplus_buy_equiv = floor(surplus_sell * buy_amount / sell_amount)
		surplusSell_mul_buyAmt := api.Mul(surplusInSurplusToken, tr.BuyAmount)
		surplusBuyEquiv := divFloor(api, rc, surplusSell_mul_buyAmt, tr.SellAmount, AMT_BITS*2, AMT_BITS, AMT_BITS+1)

		// surplus_in_buy_token:
		// Sell order: already in buy token
		// Buy order: use converted
		surplusInBuyToken := api.Select(tr.Side, surplusBuyEquiv, surplusInSurplusToken)

		// Convert to native: floor(surplus_buy * nativePriceBuy / 1e18)
		surplus_mul_price := api.Mul(surplusInBuyToken, tr.NativePriceBuy)
		scoreNative := divFloor(api, rc, surplus_mul_price, frontend.Variable(ONE_E18), AMT_BITS*2+PRICE_BITS, 60, AMT_BITS+PRICE_BITS)

		sum = api.Add(sum, api.Mul(ta, scoreNative))
	}

	return api.Select(active, sum, 0)
}

func greedySelectWinners(
	api frontend.API,
	cmps Comparators,
	sols []Solution,
	solsLen frontend.Variable,
	scores []frontend.Variable,
	pairKeys []frontend.Variable,
) [WMax]Winner {

	var winners [WMax]Winner
	for w := 0; w < WMax; w++ {
		winners[w].SolutionID = frontend.Variable(0)
		winners[w].Solver = frontend.Variable(0)
		winners[w].Score = frontend.Variable(0)
	}

	// used pair keys + a mask that marks which slots are actually used
	used := make([]frontend.Variable, WMax)
	usedMask := make([]frontend.Variable, WMax)
	for w := 0; w < WMax; w++ {
		used[w] = frontend.Variable(0)
		usedMask[w] = frontend.Variable(0) // 0/1
	}

	usedLen := frontend.Variable(0)
	winCount := frontend.Variable(0)

	for i := 0; i < NMax; i++ {
		activeI := isLessThanConst(api, cmps.LenSol, i, solsLen)

		// conflict := OR_j (usedMask[j] == 1 AND used[j] == pairKeys[i])
		conflict := frontend.Variable(0)
		for j := 0; j < WMax; j++ {
			eq := api.IsZero(api.Sub(pairKeys[i], used[j]))
			conflict = api.Or(conflict, api.Mul(usedMask[j], eq))
		}

		// canPick = activeI && !conflict && winCount < WMax
		hasSlot := isLessThanVarConst(api, cmps.LenWin, winCount, WMax)
		canPick := api.Mul(activeI, api.Mul(api.Sub(1, conflict), hasSlot))

		// If pick, write into winners[winCount]
		for w := 0; w < WMax; w++ {
			isThisSlot := api.IsZero(api.Sub(winCount, w))
			write := api.Mul(canPick, isThisSlot)

			winners[w].SolutionID = api.Select(write, sols[i].SolutionID.Value, winners[w].SolutionID)
			winners[w].Solver = api.Select(write, sols[i].Solver.Value, winners[w].Solver)
			winners[w].Score = api.Select(write, scores[i], winners[w].Score)
		}

		// If pick, append pairKey into used[usedLen] AND set usedMask[usedLen] = 1
		for w := 0; w < WMax; w++ {
			isThisSlot := api.IsZero(api.Sub(usedLen, w))
			write := api.Mul(canPick, isThisSlot)

			used[w] = api.Select(write, pairKeys[i], used[w])
			usedMask[w] = api.Select(write, frontend.Variable(1), usedMask[w])
		}

		usedLen = api.Add(usedLen, canPick)
		winCount = api.Add(winCount, canPick)
	}

	// Optional sanity checks
	// usedMask is boolean
	for w := 0; w < WMax; w++ {
		assertBoolIf(api, usedMask[w], 1)
	}

	// usedLen == sum(usedMask)
	sumMask := frontend.Variable(0)
	for w := 0; w < WMax; w++ {
		sumMask = api.Add(sumMask, usedMask[w])
	}
	api.AssertIsEqual(sumMask, usedLen)

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

// Enforces (when cond==1): a >= b over integers by introducing a small non-negative slack d:
//
//	a = b + d, with d in [0, 2^dBits)
//
// When cond==0: does nothing (d is forced to 0 via Select to keep rangecheck safe).
// dBits must be large enough to cover the maximum expected difference.
// For our amounts, AMT_BITS+1 is typically fine (already capped amt comparator at AMT_BITS+1).
func assertGeqIfRange(
	api frontend.API,
	rc frontend.Rangechecker,
	a, b, cond frontend.Variable,
	dBits int,
) (d frontend.Variable) {
	// d := a - b (field subtraction)
	d = api.Sub(a, b)

	// Bind meaning under condition: a = b + d
	// Multiply by cond so it's only enforced when cond==1.
	api.AssertIsEqual(
		api.Mul(cond, api.Sub(a, api.Add(b, d))),
		0,
	)

	// Enforce d is small non-negative integer under condition via rangecheck.
	// When cond==0, rangecheck(0) is always ok.
	dG := api.Select(cond, d, 0)
	rc.Check(dG, dBits)

	return d
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
	out, err := api.NewHint(divModHint, 2, a, b)
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

// results[0] = q = floor(a/b)
// results[1] = r = a - b*q
func divModHint(mod *big.Int, inputs []*big.Int, results []*big.Int) error {
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
