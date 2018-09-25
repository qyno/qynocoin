// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2017-2018 The Qyno Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */


static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    (0, uint256("00000f854d72cc4a91e01b634a4900f28e533bb9100f37577208c1b1ca001a54"));
static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1537781400, // * UNIX timestamp of last checkpoint block
    0,    // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    200        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1537781400,
    0,
    250};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1537781400,
    0,
    100};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        pchMessageStart[0] = 0xbf;
        pchMessageStart[1] = 0x0c;
        pchMessageStart[2] = 0x6b;
        pchMessageStart[3] = 0xbd;
        vAlertPubKey = ParseHex("04064f63fcc2211112e0c2e7b56f47e12e5969b491637ccd2fcbd88e431dc5d47e4599912ad0b3b2990d2c96959452a94e160b34899d91f1c6d555637d7399fe9f");
        nDefaultPort = 39741;
        bnProofOfWorkLimit = ~uint256(0) >> 20; // Qyno starting difficulty is 1 / 2^12
        nSubsidyHalvingInterval = 525600; // one year
        nMaxReorganizationDepth = 100;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // Qyno: every block
        nTargetSpacing = 1 * 60;  // Qyno: 1 minute
        nLastPOWBlock = 250;
        nMaturity = 100;
        nMasternodeCountDrift = 20;
        nModifierUpdateBlock = 1;
        nMaxMoneyOut = 31000000 * COIN;
        nMasternodeCollateral = 5000; 

        const char* pszTimestamp = "The 21st World Cup final will be held on Sunday, July 15, 2018";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 50 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("044696d83c60517df7c80c75a7f8dcf250aaf5639990368dfe9129650073d177ab0cc5845c436330b0bb78cd2fa5beec7f803bfff874aed469ab95cf88f7d435d0") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1537781400;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 792308;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x00000f854d72cc4a91e01b634a4900f28e533bb9100f37577208c1b1ca001a54"));
        assert(genesis.hashMerkleRoot == uint256("0xa4cdccfff9987c82ebf6815f12319fa6d132f343ba55a75f10d4f75a4f5417a9"));

        vSeeds.push_back(CDNSSeedData("1", "seed1.qyno.org"));
        vSeeds.push_back(CDNSSeedData("2", "seed2.qyno.org"));
        vSeeds.push_back(CDNSSeedData("3", "seed3.qyno.org"));
        vSeeds.push_back(CDNSSeedData("4", "seed4.qyno.org"));
        vSeeds.push_back(CDNSSeedData("5", "seed5.qyno.org"));			

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 78); // Qyno addresses start with 'Y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 10); // Qyno script addresses start with '5'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 137);    // Qyno private keys start with 'x'
		// Qyno BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
		// Qyno BIP32 pubkeys start with 'xprv' (Bitcoin defaults)		
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // 	BIP44 coin type is '0X80000a20' from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x0a)(0x20).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "044ffdb435eb289137f19a863469503163a39fda7473b6d97cff1cbb0c04d73510fc062defb6ea27cdbbd23e476680b9f0e09dae333719be79c69bfe3697cee036";
        strPrivatesendPoolDummyAddress = "YnYhniBTcvgyXiDBLBQ7jxJfYSXLTuRaUT";
        nStartMasternodePayments = 1537781400;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0xce;
        pchMessageStart[1] = 0xe2;
        pchMessageStart[2] = 0xca;
        pchMessageStart[3] = 0xff;
        vAlertPubKey = ParseHex("04c889e84faa4b99b5ce96bfb9a112fefc75b1ce78c4e60167043da29aa20ed53102100a2e83557ab133443a139d792f7ca9286a123455dae73161c97903ed2be7");
        nDefaultPort = 39743;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // Qyno: 1 day
        nTargetSpacing = 1 * 60;  // Qyno: 1 minute
        nLastPOWBlock = 200;
        nMaturity = 15;
        nMasternodeCountDrift = 4;
        nModifierUpdateBlock = 1; //approx Mon, 17 Apr 2017 04:00:00 GMT
        nMaxMoneyOut = 31000000 * COIN;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1537781400;
        genesis.nNonce = 1123994;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x0000070f3c764e439404513c49dbba649883834fa97d3ae30149d1948c1b8052"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("1", "seed1.qyno.org"));
        vSeeds.push_back(CDNSSeedData("2", "seed2.qyno.org"));
        vSeeds.push_back(CDNSSeedData("3", "seed3.qyno.org"));
        vSeeds.push_back(CDNSSeedData("4", "seed4.qyno.org"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 127); // Testnet qyno addresses start with 't'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 20);  // Testnet qyno script addresses start with '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
		// Qyno BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
		// Qyno BIP32 pubkeys start with 'xprv' (Bitcoin defaults)		
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // Testnet qyno BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strSporkKey = "046520eb740b71299b47b410b0db79612dfea0bdb62d91f5f8c6e07a186a8248bf85afe529e934b486046321dc9a6228df8f23648657bbbd1eb3044d28f5b2fc43";
        strPrivatesendPoolDummyAddress = "Yaqt3uzPecpH1DhcjweLsmu2wzVKgfukZi";
        nStartMasternodePayments = 1537781400;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdc;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 24 * 60 * 60; // Qyno: 1 day
        nTargetSpacing = 1 * 60;        // Qyno: 1 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1537781400;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 2053;

        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 39745;
        assert(hashGenesisBlock == uint256("0x219db8a1b43a3e6860e7193cd6a8183289c4ab4c405d743d6f8e150e2802798e"));

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 39111;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
