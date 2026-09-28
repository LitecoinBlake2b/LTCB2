// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

    // LTCB2: at/after the fork height, Blake2b-era difficulty rules apply.
    if (pindexLast->nHeight + 1 >= params.nBlake2bForkHeight) {
        return GetNextWorkRequiredBlake2b(pindexLast, pblock, params);
    }

    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    // Litecoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = params.DifficultyAdjustmentInterval()-1;
    if ((pindexLast->nHeight+1) != params.DifficultyAdjustmentInterval())
        blockstogoback = params.DifficultyAdjustmentInterval();

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;

    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    // Litecoin: intermediate uint256 can overflow by 1 bit
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

/**
 * LTCB2 Blake2b-era difficulty.
 *
 * Design (ported from the Litecoin Cash playbook, which used the same scheme
 * for its Scrypt -> SHA256d fork):
 *  - Grace period: the first nBlake2bMinDifficultyBlocks blocks at/after the
 *    fork are mined at minimum difficulty (powLimit), giving the cold-start
 *    Blake2b hashrate a chance to bootstrap.
 *  - Then Dark Gravity Wave v3: a per-block retarget over the last
 *    nBlake2bDGWWindow blocks, with the adjustment clamped to [1/3, 3].
 * The pre-fork Scrypt difficulty history is NOT carried over: it measures a
 * different hash function and would be meaningless for Blake2b miners.
 */
unsigned int GetNextWorkRequiredBlake2b(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    const unsigned int nProofOfWorkLimit = bnPowLimit.GetCompact();

    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    const int nHeight = pindexLast->nHeight + 1;
    const int64_t nBlocksSinceFork = (int64_t)nHeight - params.nBlake2bForkHeight;
    assert(nBlocksSinceFork >= 0);

    // Grace period: minimum difficulty while the Blake2b hashrate bootstraps.
    if (nBlocksSinceFork < params.nBlake2bMinDifficultyBlocks)
        return nProofOfWorkLimit;

    // Testnet-style minimum-difficulty rule (only active where configured).
    if (params.fPowAllowMinDifficultyBlocks &&
        pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
        return nProofOfWorkLimit;

    // Dark Gravity Wave v3: retarget every block over a short window.
    const int64_t nPastBlocks = params.nBlake2bDGWWindow;
    assert(nPastBlocks > 0);
    // The grace period is longer than the window, so every block in the
    // window is a post-fork Blake2b block.
    assert(nBlocksSinceFork >= nPastBlocks);

    const CBlockIndex* pindex = pindexLast;
    arith_uint256 bnPastTargetAvg;
    for (int64_t nCountBlocks = 1; nCountBlocks <= nPastBlocks; nCountBlocks++) {
        arith_uint256 bnTarget;
        bnTarget.SetCompact(pindex->nBits);
        if (nCountBlocks == 1) {
            bnPastTargetAvg = bnTarget;
        } else {
            // NOTE: this is not a true average, it matches the DGW reference.
            bnPastTargetAvg = (bnPastTargetAvg * nCountBlocks + bnTarget) / (nCountBlocks + 1);
        }
        if (nCountBlocks != nPastBlocks) {
            assert(pindex->pprev);
            pindex = pindex->pprev;
        }
    }

    arith_uint256 bnNew(bnPastTargetAvg);
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindex->GetBlockTime();
    const int64_t nTargetTimespan = nPastBlocks * params.nPowTargetSpacing;
    if (nActualTimespan < nTargetTimespan / 3)
        nActualTimespan = nTargetTimespan / 3;
    if (nActualTimespan > nTargetTimespan * 3)
        nActualTimespan = nTargetTimespan * 3;

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
