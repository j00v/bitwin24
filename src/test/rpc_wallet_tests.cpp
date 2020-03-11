// Copyright (c) 2013-2014 The Bitcoin Core developers
// Copyright (c) 2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/server.h"
#include "rpc/client.h"

#include "base58.h"
#include "sporkdb.h"
#include "txdb.h"
#include "wallet.h"

#include <algorithm>
#include <iterator>

#include <boost/algorithm/string.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>

using namespace std;

extern UniValue createArgs(int nRequired, const char* address1 = NULL, const char* address2 = NULL);
extern UniValue CallRPC(string args);

extern CWallet* pwalletMain;

void GenerateBlock(const std::string& minerPubKeyHex)
{
   CBlock block;
   const char* pszTimestamp = "Bitcoin is 10 years old today — here's a look back at its crazy history";
   CMutableTransaction txNew;
   txNew.vin.resize(1);
   txNew.vout.resize(1);
   txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
   txNew.vout[0].nValue = 10000 + chainActive.Tip()->nHeight;
   txNew.vout[0].scriptPubKey = CScript() << ParseHex(minerPubKeyHex) << OP_CHECKSIG;

   block.vtx.push_back(txNew);
   block.hashPrevBlock = chainActive.Tip()->GetBlockHash();
   block.hashMerkleRoot = block.BuildMerkleTree();
   block.nVersion = 1;
   block.nTime = 1572494400;
   block.nBits = 0x1e0ffff0;
   block.nNonce = 0;

   auto pindexNew = AddToBlockIndex(block);
   for (; block.nNonce < 1000000000; block.nNonce++) {
      CValidationState state;
      if (ConnectTip(state, pindexNew, &block, false)) {
         BOOST_CHECK(state.IsValid());
         break;
      }
   }
}

void AddPrivKeyToWallet(const std::string& hex, const std::string& strAccount)
{
   CPrivKey privKey;
   const auto privKeyBytes = ParseHex(hex);
   std::copy(std::begin(privKeyBytes), std::end(privKeyBytes), std::back_inserter(privKey));

   CKey key;
   key.SetPrivKey(privKey, false);
   CPubKey pubkey = key.GetPubKey();
   BOOST_CHECK(key.IsValid());
   BOOST_CHECK(key.VerifyPubKey(pubkey));
   {
      LOCK2(cs_main, pwalletMain->cs_wallet);
      auto keyId = pubkey.GetID();
      auto address = CBitcoinAddress(keyId);
      auto strAddress = address.ToString();

      BOOST_CHECK(pwalletMain->AddKeyPubKey(key, pubkey));

      if (IsMine(*pwalletMain, address.Get())) {
         pwalletMain->SetAddressBook(address.Get(), strAccount, "receive");
      }
   }
}

BOOST_AUTO_TEST_SUITE(rpc_wallet_tests)

BOOST_AUTO_TEST_CASE(rpc_addmultisig)
{
    LOCK(pwalletMain->cs_wallet);

    rpcfn_type addmultisig = tableRPC["addmultisigaddress"]->actor;

    // old, 65-byte-long:
    const char address1Hex[] = "041431A18C7039660CD9E3612A2A47DC53B69CB38EA4AD743B7DF8245FD0438F8E7270415F1085B9DC4D7DA367C69F1245E27EE5552A481D6854184C80F0BB8456";
    // new, compressed:
    const char address2Hex[] = "029BBEFF390CE736BD396AF43B52A1C14ED52C086B1E5585C15931F68725772BAC";

    UniValue v;
    CBitcoinAddress address;
    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(1, address1Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(1, address1Hex, address2Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(2, address1Hex, address2Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_THROW(addmultisig(createArgs(0), false), runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(1), false), runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(2, address1Hex), false), runtime_error);

    BOOST_CHECK_THROW(addmultisig(createArgs(1, ""), false), runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(1, "NotAValidPubkey"), false), runtime_error);

    string short1(address1Hex, address1Hex + sizeof(address1Hex) - 2); // last byte missing
    BOOST_CHECK_THROW(addmultisig(createArgs(2, short1.c_str()), false), runtime_error);

    string short2(address1Hex + 1, address1Hex + sizeof(address1Hex)); // first byte missing
    BOOST_CHECK_THROW(addmultisig(createArgs(2, short2.c_str()), false), runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_wallet)
{
    // Test RPC calls for various wallet statistics
    UniValue r;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CPubKey demoPubkey = pwalletMain->GenerateNewKey();
    CBitcoinAddress demoAddress = CBitcoinAddress(CTxDestination(demoPubkey.GetID()));
    UniValue retValue;
    string strAccount = "walletDemoAccount";
    string strPurpose = "receive";
    BOOST_CHECK_NO_THROW({ /*Initialize Wallet with an account */
        CWalletDB walletdb(pwalletMain->strWalletFile);
        CAccount account;
        account.vchPubKey = demoPubkey;
        pwalletMain->SetAddressBook(account.vchPubKey.GetID(), strAccount, strPurpose);
        walletdb.WriteAccount(strAccount, account);
    });

    CPubKey setaccountDemoPubkey = pwalletMain->GenerateNewKey();
    CBitcoinAddress setaccountDemoAddress = CBitcoinAddress(CTxDestination(setaccountDemoPubkey.GetID()));

    /*********************************
     * 			setaccount
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("setaccount " + setaccountDemoAddress.ToString() + " nullaccount"));
    /* GV71CtUgDHC5UtDo5wZppJ6CbVvEMHfQYs is not owned by the test wallet. */
    BOOST_CHECK_THROW(CallRPC("setaccount GV71CtUgDHC5UtDo5wZppJ6CbVvEMHfQYs nullaccount"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("setaccount"), runtime_error);
    /* GV71CtUgDHC5UtDo5wZppJ6CbVvEMHfQY (33 chars) is an illegal address (should be 34 chars) */
    BOOST_CHECK_THROW(CallRPC("setaccount GV71CtUgDHC5UtDo5wZppJ6CbVvEMHfQY nullaccount"), runtime_error);

    /*********************************
     * 			listunspent
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listunspent"));
    BOOST_CHECK_THROW(CallRPC("listunspent string"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("listunspent 0 string"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("listunspent 0 1 not_array"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("listunspent 0 1 [] extra"), runtime_error);
    BOOST_CHECK_NO_THROW(r = CallRPC("listunspent 0 1 []"));
    BOOST_CHECK(r.get_array().empty());

    /*********************************
     * 		listreceivedbyaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaddress"));
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaddress 0"));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaddress not_int"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaddress 0 not_bool"), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaddress 0 true"));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaddress 0 true extra"), runtime_error);

    /*********************************
     * 		listreceivedbyaccount
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaccount"));
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaccount 0"));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaccount not_int"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaccount 0 not_bool"), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaccount 0 true"));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaccount 0 true extra"), runtime_error);

    /*********************************
     * 		getrawchangeaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("getrawchangeaddress"));

    /*********************************
     * 		getnewaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("getnewaddress"));
    BOOST_CHECK_NO_THROW(CallRPC("getnewaddress getnewaddress_demoaccount"));

    /*********************************
     * 		getaccountaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("getaccountaddress \"\""));
    BOOST_CHECK_NO_THROW(CallRPC("getaccountaddress accountThatDoesntExists")); // Should generate a new account
    BOOST_CHECK_NO_THROW(retValue = CallRPC("getaccountaddress " + strAccount));
    BOOST_CHECK(CBitcoinAddress(retValue.get_str()).Get() == demoAddress.Get());

    /*********************************
     * 			getaccount
     *********************************/
    BOOST_CHECK_THROW(CallRPC("getaccount"), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("getaccount " + demoAddress.ToString()));

    /*********************************
     * 	signmessage + verifymessage
     *********************************/
    BOOST_CHECK_NO_THROW(retValue = CallRPC("signmessage " + demoAddress.ToString() + " mymessage"));
    BOOST_CHECK_THROW(CallRPC("signmessage"), runtime_error);
    /* Should throw error because this address is not loaded in the wallet */
    BOOST_CHECK_THROW(CallRPC("signmessage GV71CtUgDHC5UtDo5wZppJ6CbVvEMHfQYs mymessage"), runtime_error);

    /* missing arguments */
    BOOST_CHECK_THROW(CallRPC("verifymessage " + demoAddress.ToString()), runtime_error);
    BOOST_CHECK_THROW(CallRPC("verifymessage " + demoAddress.ToString() + " " + retValue.get_str()), runtime_error);
    /* Illegal address */
    BOOST_CHECK_THROW(CallRPC("verifymessage GV71CtUgDHC5UtDo5wZppJ6CbVvEMHfQY " + retValue.get_str() + " mymessage"), runtime_error);
    /* wrong address */
    BOOST_CHECK(CallRPC("verifymessage GV71CtUgDHC5UtDo5wZppJ6CbVvEMHfQYs " + retValue.get_str() + " mymessage").get_bool() == false);
    /* Correct address and signature but wrong message */
    BOOST_CHECK(CallRPC("verifymessage " + demoAddress.ToString() + " " + retValue.get_str() + " wrongmessage").get_bool() == false);
    /* Correct address, message and signature*/
    BOOST_CHECK(CallRPC("verifymessage " + demoAddress.ToString() + " " + retValue.get_str() + " mymessage").get_bool() == true);

    /*********************************
     * 		getaddressesbyaccount
     *********************************/
    BOOST_CHECK_THROW(CallRPC("getaddressesbyaccount"), runtime_error);
    BOOST_CHECK_NO_THROW(retValue = CallRPC("getaddressesbyaccount " + strAccount));
    UniValue arr = retValue.get_array();
    BOOST_CHECK(arr.size() > 0);
    BOOST_CHECK(CBitcoinAddress(arr[0].get_str()).Get() == demoAddress.Get());
}

BOOST_AUTO_TEST_CASE(rpc_listunspent_returns_unspent_with_zero_confirmations)
{
   ModifiableParams()->setSkipProofOfWorkCheck(true);
   zerocoinDB = new CZerocoinDB(0, false, fReindex);
   pSporkDB = new CSporkDB(0, false, false);

   AddPrivKeyToWallet("3081d30201010420fa2287e52091858b62eb12bba8460d8db9ddaefcb9fc0ff8ffeea01c49b11a4ba08185308182020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a12403220002a4aa8d6301ccd6636c014fe40212ba8a8db9f477ab57b7b41e0b3d85e49fd664", "acc1");
   AddPrivKeyToWallet("3081d302010104203920dab8e739167143c207ff447e2e8eec06e0468fdde01b0ad02c1fa8f96718a08185308182020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a124032200025777aa773e88bbbf2b31fb859d4e3c73b527b6f1fb12fffdd6b331ab585c1cbd", "acc2");
   for (size_t i = 0; i < 120; i++) {
      GenerateBlock("04a4aa8d6301ccd6636c014fe40212ba8a8db9f477ab57b7b41e0b3d85e49fd664cc373a19dfb5751653dc4c77c24686596e3774153e35e60e100f48fc32f317c4");
   }
   BOOST_CHECK(pwalletMain->GetBalance() > 0);

   UniValue r;
   BOOST_CHECK_NO_THROW(r = CallRPC("listunspent 0 9999999 [\"GRg9dophuqVNUXe8BzpywcMKFxbWYL9Nw4\"]").get_array());
   BOOST_REQUIRE(r.size() == 0);

   BOOST_CHECK_NO_THROW(r = CallRPC("sendfrom acc1 GRg9dophuqVNUXe8BzpywcMKFxbWYL9Nw4 0.00010000"));

   BOOST_CHECK_NO_THROW(r = CallRPC("listunspent 0 9999999 [\"GRg9dophuqVNUXe8BzpywcMKFxbWYL9Nw4\"]").get_array());
   BOOST_REQUIRE(r.size() == 1);
   const auto obj = r[0].get_obj();
   BOOST_CHECK(obj["confirmations"].get_int64() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
