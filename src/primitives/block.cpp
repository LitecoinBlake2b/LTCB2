// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/params.h>
#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <crypto/common.h>
#include <crypto/blake2b.h>
#include <crypto/scrypt.h>

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetPoWHash(int nHeight, const Consensus::Params& consensusParams) const
{
    // The serialized header is exactly 80 bytes (no vtable, no padding);
    // both PoW hash functions digest the full 80-byte header.
    static_assert(sizeof(CBlockHeader) == 80, "CBlockHeader must be exactly 80 bytes for PoW hashing");
    uint256 thash;
    if (nHeight >= consensusParams.nBlake2bForkHeight) {
        // LTCB2: Blake2b-256 over the 80-byte header for blocks at/after the fork.
        blake2b(BEGIN(thash), 32, BEGIN(nVersion), 80, nullptr, 0);
    } else {
        scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
    }
    return thash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

CTransactionRef CBlock::GetHogEx() const noexcept
{
    if (vtx.size() >= 2 && vtx.back()->IsHogEx()) {
        assert(!vtx.back()->vout.empty());
        return vtx.back();
    }

    return nullptr;
}