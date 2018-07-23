// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The Qyno Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The 21st World Cup final will be held on Sunday, July 15, 2018";
    const CScript genesisOutputScript = CScript() << ParseHex("04249d7766f79617299beee3fbc9a27b846a264540a63730eada24f8b2974399196082848552904237f1b66e7c474c0ff6367eb4eb7c79b376c29ca8b887fdcc9e") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 525600; // one year
        consensus.nMasternodePaymentsStartBlock = 100; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 158000; // false
        consensus.nMasternodePaymentsIncreasePeriod = 576*30; // false
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 1000000000; // prepare for next release
        consensus.nBudgetPaymentsCycleBlocks = 100000; // prepare for next release
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nBudgetProposalEstablishingTime = 60*60*24;
        consensus.nSuperblockStartBlock = 1000000001; // prepare for next release
        consensus.nSuperblockCycle = 100000; // prepare for next release
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x0000009fe4cf87f5dc22418c05ef23b82e1b05f1e29f4b7a1fa7bafa596c7669");
        consensus.powLimit = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 60 * 60; // Qyno: 1 hour, 60 blocks
        consensus.nPowTargetSpacing =       60; // Qyno: 1 minute
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nPowKGWHeight = 120;
        consensus.nPowDGWHeight = 120;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1531656000; // 07/15/2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1563105600; // 07/14/2019

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 1531656000; // 05/01/2018
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 1563105600; // 07/14/2019
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 1000;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 800; // 80% of 1000

        // The best chain should have at least this much work.
		consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000208977a9152c1");  // 10935

        // By default assume that the signatures in ancestors of this block are valid.
		consensus.defaultAssumeValid = uint256S("0x0000000007420efe2b862ccd5f5eb2e771b7648609b00b6c2efc14f047b62762");  // 10935 block hash

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xbf;
        pchMessageStart[1] = 0x0c;
        pchMessageStart[2] = 0x6b;
        pchMessageStart[3] = 0xbd;
        vAlertPubKey = ParseHex("047e9e5060118bd819aafc55f580c6b96af2f1ade3a5dea9157088fd28721f9d2656bace4fd7a3afd2a95c945b334db9aaa0a9066d59160fbaf3726dcedbe73272");
        nDefaultPort = 37110;
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin
        nDelayGetHeadersTime = 24 * 60 * 60;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1531656000, 3596559, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000009fe4cf87f5dc22418c05ef23b82e1b05f1e29f4b7a1fa7bafa596c7669"));
        assert(genesis.hashMerkleRoot == uint256S("0x8189c5958905dd5ea0b9957c438c21427188a4c747b93eefd832e83f4508fc64"));

        vSeeds.push_back(CDNSSeedData("1", "seed1.qyno.org"));
        vSeeds.push_back(CDNSSeedData("2", "seed2.qyno.org"));
        vSeeds.push_back(CDNSSeedData("3", "seed3.qyno.org"));
        vSeeds.push_back(CDNSSeedData("4", "seed4.qyno.org"));

        // Qyno addresses start with 'Q'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,58);
        // Qyno script addresses start with '5'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,10);
        // Qyno private keys start with 'x' or 'y'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,139);
        // Qyno BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // Qyno BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        // Qyno BIP44 coin type is '5'
        nExtCoinType = 5;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour
        strSporkPubKey = "0463740b9872f4e436467e73794400039e6aa74a7e4a05ab179b5efc8b27281a4fb4a4857c8b032ae8df62955c2dfe17793a97d7928ec23c484e2a1199d2793ddc";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (        0, uint256S("0x0000009fe4cf87f5dc22418c05ef23b82e1b05f1e29f4b7a1fa7bafa596c7669"))
			(    11000, uint256S("0x000000001fd6e9ee87948059625c59793dee34dd1ec35bedec3b104a0678e66d")),
            1532347627, // * UNIX timestamp of last checkpoint block
                 18063, // * total number of transactions between genesis and last checkpoint(the tx=... number in the SetBestChain debug.log lines)
                  5000  // * estimated number of transactions per day after checkpoint
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 525600; // one year
        consensus.nMasternodePaymentsStartBlock = 100; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 158000; // false
        consensus.nMasternodePaymentsIncreasePeriod = 576*30; // false
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000000000; // prepare for next release
        consensus.nBudgetPaymentsCycleBlocks = 100000; // prepare for next release
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nBudgetProposalEstablishingTime = 60*60*24;
        consensus.nSuperblockStartBlock = 1000000001; // prepare for next release
        consensus.nSuperblockCycle = 100000; // prepare for next release
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x0000038b17774e6cfe0aff4fcaaa04bad829ac8ecab7e28db61dc14365ddb7e4");
        consensus.powLimit = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 60 * 60; // Qyno: 1 hour, 60 blocks
        consensus.nPowTargetSpacing =       60; // Qyno: 1 minute
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nPowKGWHeight = 101;
        consensus.nPowDGWHeight = 101;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1531656000; // 07/15/2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1563105600; // 07/14/2019

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 1531656000; // 07/15/2018
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 1563105600; // 07/14/2019
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 50; // 80% of 1500

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00"); // 0

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000038b17774e6cfe0aff4fcaaa04bad829ac8ecab7e28db61dc14365ddb7e4"); // 0

        pchMessageStart[0] = 0xce;
        pchMessageStart[1] = 0xe2;
        pchMessageStart[2] = 0xca;
        pchMessageStart[3] = 0xff;
        vAlertPubKey = ParseHex("04f27af01846c2cf7647a1079724623983b10f93e1b521e3bf8ac6f6f6d1befbf03459d4b21f56c3a6348895c1b3c5b35235711dddce39b3b5fd8c8fbfa5621716");
        nDefaultPort = 37112;
        nMaxTipAge = 0x7fffffff; // allow mining on top of old blocks for testnet
        nDelayGetHeadersTime = 24 * 60 * 60;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1531656001, 430927, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000038b17774e6cfe0aff4fcaaa04bad829ac8ecab7e28db61dc14365ddb7e4"));
        assert(genesis.hashMerkleRoot == uint256S("0x8189c5958905dd5ea0b9957c438c21427188a4c747b93eefd832e83f4508fc64"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("1", "seed1.qyno.org"));
        vSeeds.push_back(CDNSSeedData("2", "seed2.qyno.org"));

        // Testnet Qyno addresses start with 'q'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,120);
        // Testnet Qyno script addresses start with '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,20);
        // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Testnet Qyno BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet Qyno BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        // Testnet Qyno BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        strSporkPubKey = "040f517d86d764de8e1f96d2457dd8f238a42d4f8686df5a5502730d28cc44260fff936c0e221434287037b808fcaf6658a2e1f2316744b635eaf691d3076ba7ba";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (        0, uint256S("0x0000038b17774e6cfe0aff4fcaaa04bad829ac8ecab7e28db61dc14365ddb7e4")),

            1531656001, // * UNIX timestamp of last checkpoint block
            0,          // * total number of transactions between genesis and last checkpoint(the tx=... number in the SetBestChain debug.log lines)
            500         // * estimated number of transactions per day after checkpoint
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 525600; // one year
        consensus.nMasternodePaymentsStartBlock = 100; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 158000; // false
        consensus.nMasternodePaymentsIncreasePeriod = 576*30; // false
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000000000; // prepare for next release
        consensus.nBudgetPaymentsCycleBlocks = 100000; // prepare for next release
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nBudgetProposalEstablishingTime = 60*60*24;
        consensus.nSuperblockStartBlock = 1000000001; // prepare for next release
        consensus.nSuperblockCycle = 100000; // prepare for next release
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60; // Qyno: 1 hour, 60 blocks
        consensus.nPowTargetSpacing =       60; // Qyno: 1 minute
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nPowKGWHeight = 120; // same as mainnet
        consensus.nPowDGWHeight = 120; // same as mainnet
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdc;
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin
        nDelayGetHeadersTime = 0; // never delay GETHEADERS in regtests
        nDefaultPort = 37114;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1531656002, 1, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x22e9038b6b533041f305242fb034de03a9ca081422937b49b4e8883852953cdd"));
        assert(genesis.hashMerkleRoot == uint256S("0x8189c5958905dd5ea0b9957c438c21427188a4c747b93eefd832e83f4508fc64"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            (        0, uint256S("0x22e9038b6b533041f305242fb034de03a9ca081422937b49b4e8883852953cdd")),
            1531656002,
            0,
            0
        };
        // Regtest Qyno addresses start with 'q'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,120);
        // Regtest Qyno script addresses start with '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,20);
        // Regtest private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Regtest Qyno BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Regtest Qyno BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        // Regtest Qyno BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;
   }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}
