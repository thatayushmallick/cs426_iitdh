#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <unordered_map>
#include <thread>
#include <random>
#include <chrono>

using namespace std;

// Function to compute SHA-256 hash
// string sha256(const string &input) {
//     unsigned char hash[SHA256_DIGEST_LENGTH];
//     SHA256_CTX sha256;
//     SHA256_Init(&sha256);
//     SHA256_Update(&sha256, input.c_str(), input.size());
//     SHA256_Final(hash, &sha256);
//     stringstream ss;
//     for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
//         ss << hex << setw(2) << setfill('0') << (int)hash[i];
//     }
//     return ss.str();
// }
string sha256(const string& input) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int length = 0;
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, input.c_str(), input.size());
    EVP_DigestFinal_ex(ctx, hash, &length);
    EVP_MD_CTX_free(ctx);
    stringstream ss;
    for (unsigned int i = 0; i < length; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// -------------------------
// Block Class
// -------------------------
class Block {
public:
    // TODO: Define the fields for the block (parentHash, nonce, difficulty, timestamp, merkleRoot, transactions, hash)
    string parentHash;
    int nonce;
    string difficulty;
    time_t timestamp;
    string merkleRoot;
    vector<string> transactions;
    string hash;

    // Default constructor
    Block() : parentHash(""), nonce(0), difficulty(""), transactions({}) {}
    
    // Parametrized constructor
    // Block(/* TODO: Add parameters */)
    Block(string parentHash, int nonce, string difficulty, vector<string> transactions) : parentHash(parentHash), nonce(nonce), difficulty(difficulty), transactions(transactions) {
        // TODO: Initialize the block fields
        timestamp = time(nullptr);
        merkleRoot = calculateMerkleRoot(transactions);
        hash = calculateHash();
    }

    // TODO: Implement a function to calculate the hash of the block
    string calculateHash() const {
        // TODO: Combine fields like parentHash, merkleRoot, nonce, timestamp into a single string and hash it
        stringstream ss;
        ss << parentHash << nonce << difficulty << timestamp << merkleRoot;
        return sha256(ss.str());
    }

    // TODO: Implement a static function to calculate the Merkle root from transactions
    static string calculateMerkleRoot(const vector<string> &transactions) {
        // TODO: Hash the concatenated transactions
        string combined;
        for (const auto &tx : transactions) {
            combined += tx;
        }
        return sha256(combined);
    }
};

// -------------------------
// Blockchain Class
// -------------------------
class Blockchain {
private:
    // TODO: Define a vector or container to store the chain of blocks
    unordered_map<string, Block> chain;
    vector<string> blockOrder;
    string tip;

public:
    Blockchain() {
        // TODO: Create the Genesis block and add it to the chain
        Block genesisBlock("0", 0, "0000000000000000000000000000000000000000", {"Genesis Tx1", "Genesis Tx2"});
        chain[genesisBlock.hash] = genesisBlock;
        blockOrder.push_back(genesisBlock.hash);
        tip = genesisBlock.hash;
        cout << "Genesis block created with hash: " << tip << endl;
    }

    // TODO: Implement a function to add a new block to the blockchain
    void addBlock(const vector<string> &transactions) {
        // TODO: Use the latest block to generate the next block and add it to the chain
        Block newBlock(tip, chain.size() * 1000, "0000000000000000000000000000000000000000", transactions);
        chain[newBlock.hash] = newBlock;
        blockOrder.push_back(newBlock.hash);
        tip = newBlock.hash;

        // Display block details
        displayBlock(newBlock);
    }

    // TODO: Implement a function to display block details
    void displayBlock(const Block &block) const {
        // TODO: Print the fields of the block
        cout << "------ New Block ------\n";
        cout << "Parent Hash: " << block.parentHash << endl;
        cout << "Nonce: " << block.nonce << endl;
        cout << "Difficulty: " << block.difficulty << endl;
        cout << "Timestamp: " << block.timestamp << endl;
        cout << "Merkle Root: " << block.merkleRoot << endl;
        cout << "Hash: " << block.hash << endl;
        cout << "Current Blockchain Height: " << chain.size() - 1 << endl;
        cout << "-----------------------------\n";
    }

    // TODO: Implement a function to display the blockchain hashes
    void displayBlockchainHashes() const {
        // TODO: Display the hashes of all blocks in the chain from Genesis to Tip
        cout << "Blockchain from Genesis to Tip:" << endl;
        for (const auto& hash : blockOrder) {
            cout << "Block Hash: " << hash << endl;
        }

        // Display the hashes of all blocks in the chain from Tip to Genesis
        cout << "\nBlockchain from Tip to Genesis:" << endl;
        for (auto it = blockOrder.rbegin(); it != blockOrder.rend(); ++it) {
            cout << "Block Hash: " << *it << endl;
        }
    }
};

// Mining Function
void minerThread(Blockchain& blockchain, int minerId, int numBlocks) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(500, 750); // Random delay between 500-750ms

    for (int i = 1; i <= numBlocks; i++) {
        string tx1 = "Miner" + to_string(minerId) + "_Tx1_" + to_string(i);
        string tx2 = "Miner" + to_string(minerId) + "_Tx2_" + to_string(i);
        blockchain.addBlock({tx1, tx2});

        this_thread::sleep_for(chrono::milliseconds(dis(gen))); // Simulate mining delay
    }
}

// -------------------------
// Main Function
// -------------------------
int main() {
    // TODO: Create a Blockchain object
    Blockchain blockchain;

    // TODO: Add blocks with dummy transactions to the blockchain
    const int numMiners = 5;
    const int blocksPerMiner = 10;
    vector<thread> miners;

    // Launch miner threads
    for (int i = 1; i <= numMiners; i++) {
        miners.emplace_back(minerThread, ref(blockchain), i, blocksPerMiner);
    }

    // Join all threads
    for (auto& miner : miners) {
        miner.join();
    }
    
    // TODO: Display the details of the blockchain
    blockchain.displayBlockchainHashes();

    return 0;
}

// Sample Output
/*
Genesis block created with hash: cf97cc4aa82fa5bbb36153e13e3f01937358b281cfcd460b1b493176cbac872d
------ New Block ------
Parent Hash: cf97cc4aa82fa5bbb36153e13e3f01937358b281cfcd460b1b493176cbac872d
Nonce: 1000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773896
Merkle Root: bd5144656381fddc94fa42f3d171f62e9026c38c7ed70e7079245d0b03818a34
Hash: 58e157769bc49da04544134582b90be608bc7b025fdd213add2aa0126ea9527e
Current Blockchain Height: 1
-----------------------------
------ New Block ------
Parent Hash: 58e157769bc49da04544134582b90be608bc7b025fdd213add2aa0126ea9527e
Nonce: 2000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773896
Merkle Root: d874a53af9253a54311d182390e46535b83676421da9109fe063a525d89358e9
Hash: def241baee86ddac0a62ef3a00f134e1236747b6cf4214e2ec54271bcb3e70a7
Current Blockchain Height: 2
-----------------------------
------ New Block ------
Parent Hash: 58e157769bc49da04544134582b90be608bc7b025fdd213add2aa0126ea9527e
Nonce: 2000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773896
Merkle Root: 8fc4b6fda2cd3c643e4c2ec35e14239922447f963b9fac1ae8f0f35e999a3ee4
Hash: 27bae4acf9122c4fca0d2549d1383480a62a40574e8633135c0b8e63a915152a
Current Blockchain Height: 3
-----------------------------
------ New Block ------
Parent Hash: 27bae4acf9122c4fca0d2549d1383480a62a40574e8633135c0b8e63a915152a
Nonce: 4000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773896
Merkle Root: c8a5f931db0f9efba4b316b1ad6013daadfe62251f2c62bc05eb6d41e42336b5
Hash: 2d3e784400b13f4e7f70b8d5ee0a9e8da73e87ef89cddcc04776cae86a320018
Current Blockchain Height: 4
-----------------------------
------ New Block ------
Parent Hash: 2d3e784400b13f4e7f70b8d5ee0a9e8da73e87ef89cddcc04776cae86a320018
Nonce: 5000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773896
Merkle Root: 3f3ed6c7ab5267473fa61b336912081ac76b383e5da5a5a23885a500cd11c79b
Hash: 1e2024aa21dc422cf21a9c744889e1232b6ecdb7ce74aa3a70493c49fc275ab4
Current Blockchain Height: 5
-----------------------------
------ New Block ------
Parent Hash: 1e2024aa21dc422cf21a9c744889e1232b6ecdb7ce74aa3a70493c49fc275ab4
Nonce: 6000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773897
Merkle Root: b1566fa529df6e475157048ff8b91e06b01d06e1b9ede7330bae57c29f715c48
Hash: 490df40a6bc984c3040def14bd064457b8f17e94ffd34ab2d1a6afaa16b1d628
Current Blockchain Height: 6
-----------------------------
------ New Block ------
Parent Hash: 490df40a6bc984c3040def14bd064457b8f17e94ffd34ab2d1a6afaa16b1d628
Nonce: 7000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773897
Merkle Root: 9abbd8d8036306f3ee0d00b7b85bf4de9e146651171ff5e6c7c6fe01cb9b3f21
Hash: e32f61780c070a701257cab2361039da52ae031fe5ca8f850abb94b19e89e0af
Current Blockchain Height: 7
-----------------------------
------ New Block ------
Parent Hash: e32f61780c070a701257cab2361039da52ae031fe5ca8f850abb94b19e89e0af
Nonce: 8000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773897
Merkle Root: fd71c2efdd8135874ec4b5f5eacdb93b792c4b34e3c982f63d587621f2b1a194
Hash: 74146897a5ed6e945f1f418357dde0da773172e481d827bdd67a785c2793902b
Current Blockchain Height: 8
-----------------------------
------ New Block ------
Parent Hash: 74146897a5ed6e945f1f418357dde0da773172e481d827bdd67a785c2793902b
Nonce: 9000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773897
Merkle Root: 55a744f10bbf55d4b2292cf6d683199f38c4d18aca6fb0a3c9d4f6af82b59110
Hash: 56736ae540b204a2ddad29a676040c53d32623184c95381c004c4d1ee87ad4db
Current Blockchain Height: 9
-----------------------------
------ New Block ------
Parent Hash: 56736ae540b204a2ddad29a676040c53d32623184c95381c004c4d1ee87ad4db
Nonce: 10000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773897
Merkle Root: d6878bb62cc93b8bf412eba0b5e8d0d8af1542b57ee748f71fc1671b4f227a88
Hash: 71722720cb96762e65564114566d4ab6162e806f34de3f84fb66fc7fb50555e0
Current Blockchain Height: 10
-----------------------------
------ New Block ------
Parent Hash: 71722720cb96762e65564114566d4ab6162e806f34de3f84fb66fc7fb50555e0
Nonce: 11000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773897
Merkle Root: ea1d2fde55d63e5601f706fb688d83e2fdd14eb6fd0f7b91c79e715877f4468f
Hash: f64ef46bc2f88efcafe48f1f55872d0af6ec3e21028255d6fbcbe7c37530d750
Current Blockchain Height: 11
-----------------------------
------ New Block ------
Parent Hash: f64ef46bc2f88efcafe48f1f55872d0af6ec3e21028255d6fbcbe7c37530d750
Nonce: 12000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773897
Merkle Root: a150ad87e4c0bfff9bd8e850bda76a42b5feed3cf72b9e638d3af73552760ee4
Hash: b23c97e0f571c62a9bc85d3ccbbfa8f6abf7cb0e296bf1df2ea037b99d1954ad
Current Blockchain Height: 12
-----------------------------
------ New Block ------
Parent Hash: b23c97e0f571c62a9bc85d3ccbbfa8f6abf7cb0e296bf1df2ea037b99d1954ad
Nonce: 13000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773897
Merkle Root: 28a2008e087b9f2b5715df57c779e558dfc1f2118820377290c5c1da09d5fae4
Hash: bb894e66d835d7b34da2837f1682367be8627747790c2471220b651a54602402
Current Blockchain Height: 13
-----------------------------
------ New Block ------
Parent Hash: bb894e66d835d7b34da2837f1682367be8627747790c2471220b651a54602402
Nonce: 14000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773897
Merkle Root: 464e172e23c78a39c134eba73f5a88311a62b98c56a1446ec7d0529c80a96848
Hash: c4f6395fc2c8dbd2dd3d4ad8320d02b0368c218bb1e08f508e95215109388bd0
Current Blockchain Height: 14
-----------------------------
------ New Block ------
Parent Hash: c4f6395fc2c8dbd2dd3d4ad8320d02b0368c218bb1e08f508e95215109388bd0
Nonce: 15000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773898
Merkle Root: ef1414c228a0657f735898e2c613a7d1157c7b524f51d2abe69e4c4feb099ced
Hash: 76bdb6b813d5472f0249474ca6ac5417d4b9e5c2a9b7159f622e17991685d1bd
Current Blockchain Height: 15
-----------------------------
------ New Block ------
Parent Hash: 76bdb6b813d5472f0249474ca6ac5417d4b9e5c2a9b7159f622e17991685d1bd
Nonce: 16000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773898
Merkle Root: 5103c898d31ba596012cb239943ad86a406f02b6f9e4b67de8be60bd74f1d5d7
Hash: 9c2b23ebefd1e75261b57a35222466c1226cc41ab21925d5da776559a62bd618
Current Blockchain Height: 16
-----------------------------
------ New Block ------
Parent Hash: 9c2b23ebefd1e75261b57a35222466c1226cc41ab21925d5da776559a62bd618
Nonce: 17000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773898
Merkle Root: 8485ef73a29470084cdba1fdf4f73dd6b29157eeabec3f49f9320ac79514f021
Hash: 0bd3b611af7de663141e661cd11a7084173cf7d26dbd097be56abe9e4001a45f
Current Blockchain Height: 17
-----------------------------
------ New Block ------
Parent Hash: 0bd3b611af7de663141e661cd11a7084173cf7d26dbd097be56abe9e4001a45f
Nonce: 18000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773898
Merkle Root: b5ad3c754f2ba083f0ac0c47d810534dfdb9a23b997ff9c3c1ed2f724e7ae79f
Hash: 88a33ecd765e19991b83b66a9412db44443666d3c393de040f4aa7897887527d
Current Blockchain Height: 18
-----------------------------
------ New Block ------
Parent Hash: 88a33ecd765e19991b83b66a9412db44443666d3c393de040f4aa7897887527d
Nonce: 19000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773898
Merkle Root: 36c914a1cef1bab80bd47a6e0944f0a999ec24ec241825410ef8a75230d2cbb3
Hash: 982f9ef13e1be803e52c4235c94ef8dfa4071365961ed223a7e3c6d23a29f15a
Current Blockchain Height: 19
-----------------------------
------ New Block ------
Parent Hash: 982f9ef13e1be803e52c4235c94ef8dfa4071365961ed223a7e3c6d23a29f15a
Nonce: 20000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773898
Merkle Root: 6acb54849263c3edd3ca5d0ee94e33d69ddf4f3b46b03bf31ccfdb29abd2b8ee
Hash: 1238386f43a48ddeaa7c4958d85164eaa85ca17d1cb83e3a76deeadb4bcbc8a4
Current Blockchain Height: 20
-----------------------------
------ New Block ------
Parent Hash: 1238386f43a48ddeaa7c4958d85164eaa85ca17d1cb83e3a76deeadb4bcbc8a4
Nonce: 21000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773898
Merkle Root: f32b1b166f1032c8b278f35b7bfa8290ab4957db7171cf9fb262cbc0262e9373
Hash: 5120ab0eb9fbb7d2c3c59d9ffc5359be3fc45d2f35d21c10bbf68af99012b43a
Current Blockchain Height: 21
-----------------------------
------ New Block ------
Parent Hash: 5120ab0eb9fbb7d2c3c59d9ffc5359be3fc45d2f35d21c10bbf68af99012b43a
Nonce: 22000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773899
Merkle Root: 30f2b4c768c7925e8e3ad908904bd7b2bf3326583f8d007fb36db291d7c8acdd
Hash: 2be51ebcd91cc81dfc069808327780b501620a0f7e09010c281fe9060b699570
Current Blockchain Height: 22
-----------------------------
------ New Block ------
Parent Hash: 2be51ebcd91cc81dfc069808327780b501620a0f7e09010c281fe9060b699570
Nonce: 23000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773899
Merkle Root: 0823f13fbe3d1afdc493867ec0d41762ce83e25c2554198ac1eac4212d4e6edb
Hash: 29eb874be1f7e170b549b4e6e550bfa0adac9b7c51d29003b53e966611d73b68
Current Blockchain Height: 23
-----------------------------
------ New Block ------
Parent Hash: 29eb874be1f7e170b549b4e6e550bfa0adac9b7c51d29003b53e966611d73b68
Nonce: 24000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773899
Merkle Root: dd7767f28202d62816ee9e94ecb42c8bcd480336413b9baa86c5241a978d2d1f
Hash: 651eb0dc11623a97d14822f3e0b183d76e32f9d810bf2b2ac02a09711c3a8f98
Current Blockchain Height: 24
-----------------------------
------ New Block ------
Parent Hash: 651eb0dc11623a97d14822f3e0b183d76e32f9d810bf2b2ac02a09711c3a8f98
Nonce: 25000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773899
Merkle Root: c816e9c60ddcf01e950f2a67026ffa5fa635003ce6c38188c4db6ecbca2072a5
Hash: 0cf9309cc003c11fd901948e2a6aac4eae446865edade17937a048cfba3b7cf2
Current Blockchain Height: 25
-----------------------------
------ New Block ------
Parent Hash: 0cf9309cc003c11fd901948e2a6aac4eae446865edade17937a048cfba3b7cf2
Nonce: 26000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773899
Merkle Root: 4805f361f07cb649bb84d6a1e27083457009790cdceb8709c1e3e3c3034f0ff2
Hash: bb495d174d92799f9179e3a79a5a317941b6dd7a168e7de05cb18b3dda166b8e
Current Blockchain Height: 26
-----------------------------
------ New Block ------
Parent Hash: bb495d174d92799f9179e3a79a5a317941b6dd7a168e7de05cb18b3dda166b8e
Nonce: 27000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773899
Merkle Root: 6ae2893483569d5838950586c08760e66fb69d6659292d67aa071bcf80324aaa
Hash: fa69e1ac48fae941f4d71c02db8c606e0d8cf2da636d105f83ad3548b6c730d8
Current Blockchain Height: 27
-----------------------------
------ New Block ------
Parent Hash: fa69e1ac48fae941f4d71c02db8c606e0d8cf2da636d105f83ad3548b6c730d8
Nonce: 28000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773899
Merkle Root: e74adfb865b4356b62727e64894e4a13ce93192d624348a1c37c0ea3767cdcc4
Hash: 4460cd5757cb151892f95f8aa5e7868fc7cd434903b2b2545e8dab83d1d67cbc
Current Blockchain Height: 28
-----------------------------
------ New Block ------
Parent Hash: 4460cd5757cb151892f95f8aa5e7868fc7cd434903b2b2545e8dab83d1d67cbc
Nonce: 29000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773899
Merkle Root: 4db263f58599938080da6ebd3b93a0d1e8863435a600f5b542874cb48062026c
Hash: 3e4b68ac83a1081fdb63401eb21097aa35f94c805c630657c31b7d500003531b
Current Blockchain Height: 29
-----------------------------
------ New Block ------
Parent Hash: 3e4b68ac83a1081fdb63401eb21097aa35f94c805c630657c31b7d500003531b
Nonce: 30000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773900
Merkle Root: e26869e53363471537f3f05a5b88596c80b275e06e0f85a5287924ea6ec6e88c
Hash: 81cb631d4ad5df8ca4f5dc472b73845c02773561c1a8ff25fc0e9ca00251e21d
Current Blockchain Height: 30
-----------------------------
------ New Block ------
Parent Hash: 81cb631d4ad5df8ca4f5dc472b73845c02773561c1a8ff25fc0e9ca00251e21d
Nonce: 31000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773900
Merkle Root: 7a919a40aef7e35fd5481ea55411b4810f12f1c19b48a7586d12234801671667
Hash: de74f401bdbce1c2b48157eaf3b8f6ff795ee8c498db013160f6137751faf1fd
Current Blockchain Height: 31
-----------------------------
------ New Block ------
Parent Hash: de74f401bdbce1c2b48157eaf3b8f6ff795ee8c498db013160f6137751faf1fd
Nonce: 32000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773900
Merkle Root: d052fd146ed139cc7bb83920d6c730fa49ec7478957d5f772b0d56208d4c883e
Hash: 0634fc09df021872d0b3bf6b383730a51c7b49769c58b5511eab152f0a003e12
Current Blockchain Height: 32
-----------------------------
------ New Block ------
Parent Hash: 0634fc09df021872d0b3bf6b383730a51c7b49769c58b5511eab152f0a003e12
Nonce: 33000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773900
Merkle Root: 894a1517a71f069a4c27d56c5095aa160ece36181abd348c74e8ab4ebf773685
Hash: 140b85e0215039d5fd4733028ecc8d1839a039166244af3d8c9701a03eb0a064
Current Blockchain Height: 33
-----------------------------
------ New Block ------
Parent Hash: 140b85e0215039d5fd4733028ecc8d1839a039166244af3d8c9701a03eb0a064
Nonce: 34000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773900
Merkle Root: f74decba11b225011a4ed05473f04bf5e96c6f83b721f0f479cccae05bef513a
Hash: 3e6b8f065447eb169b752ed39864a15b7c2de3d847358f8aebb85624c3643f42
Current Blockchain Height: 34
-----------------------------
------ New Block ------
Parent Hash: 3e6b8f065447eb169b752ed39864a15b7c2de3d847358f8aebb85624c3643f42
Nonce: 35000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773900
Merkle Root: 34c618bce4a203b4a760a8d3ca13b8002fd6f72c05da7c69b31e866fa05fbc22
Hash: 6dddb03982fc2fe8db82cfa4c85eca339f7a5343e02f8c5a34c7b33c8f70efb1
Current Blockchain Height: 35
-----------------------------
------ New Block ------
Parent Hash: 6dddb03982fc2fe8db82cfa4c85eca339f7a5343e02f8c5a34c7b33c8f70efb1
Nonce: 36000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773900
Merkle Root: 10c6aa901464acf5ea68880556e4c354fd7cc2f59591729e6ce2346d70a8ccd6
Hash: ebb164824c2f02ee3a44af226a9b2fcfc69002ae1aac1bf8061ea711ed39407c
Current Blockchain Height: 36
-----------------------------
------ New Block ------
Parent Hash: ebb164824c2f02ee3a44af226a9b2fcfc69002ae1aac1bf8061ea711ed39407c
Nonce: 37000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773900
Merkle Root: 978ddd10211380d0401d3c44f41319e4b011ecbaa1f2b23e6c3f7c9cc2223a5a
Hash: abba0d11a93bd6361cd38b8a75986cce3617a80b5448f9a39ab460bbef6c07b3
Current Blockchain Height: 37
-----------------------------
------ New Block ------
Parent Hash: abba0d11a93bd6361cd38b8a75986cce3617a80b5448f9a39ab460bbef6c07b3
Nonce: 38000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773901
Merkle Root: f242c776b77958fcf1f1ba4abee6a0ffc0cf30f0fdcfcf21927f5b1c399f1a2e
Hash: 78a6995f921736ec400d283a73c280c595b37390ca2240d9b4513f87c2e8beb8
Current Blockchain Height: 38
-----------------------------
------ New Block ------
Parent Hash: 78a6995f921736ec400d283a73c280c595b37390ca2240d9b4513f87c2e8beb8
Nonce: 39000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773901
Merkle Root: f2fa578d6c08438dc87214990a63c9bae3e5665ae12144e7d60c9ecf34d7bc52
Hash: 10dad826abd55c5efd513c64ebb5e9018dc62b6cec6dabeee1e3bc301d8fe341
Current Blockchain Height: 39
-----------------------------
------ New Block ------
Parent Hash: 10dad826abd55c5efd513c64ebb5e9018dc62b6cec6dabeee1e3bc301d8fe341
Nonce: 40000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773901
Merkle Root: 5d1e34b65687ae6206a43ef28117cf8ca030871701ad4cc4a559571767757a33
Hash: e87bd312645870a5ae3e1e5a23f5e507267365920e70f4d7018fe0c5934733c5
Current Blockchain Height: 40
-----------------------------
------ New Block ------
Parent Hash: e87bd312645870a5ae3e1e5a23f5e507267365920e70f4d7018fe0c5934733c5
Nonce: 41000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773901
Merkle Root: 531e1247c939a31f643ea7c94b33399abc6d274358108e991e5b0feb2f918b9e
Hash: 60d699bcf742842a3ac4ae5b7aecbf9b170a2c9f18afc2247d500a6a38c98480
Current Blockchain Height: 41
-----------------------------
------ New Block ------
Parent Hash: 60d699bcf742842a3ac4ae5b7aecbf9b170a2c9f18afc2247d500a6a38c98480
Nonce: 42000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773901
Merkle Root: fca090c50d20d97b870e8a2540573785d56faa9af944d2c7ed1e560892fa0a68
Hash: be0f4453cf34688fe7479b3d85c2671e04ae2a4f7db88fef4c6090cb2e696507
Current Blockchain Height: 42
-----------------------------
------ New Block ------
Parent Hash: be0f4453cf34688fe7479b3d85c2671e04ae2a4f7db88fef4c6090cb2e696507
Nonce: 43000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773901
Merkle Root: 7e616af77c3ec722a4a826b1c2b31300fb00b4c412ae601297fdbbde91c5be2a
Hash: d4e598cb46ef2b954ada57524d6b454334b3e34d9a49a5b382f54e74d36f22c6
Current Blockchain Height: 43
-----------------------------
------ New Block ------
Parent Hash: d4e598cb46ef2b954ada57524d6b454334b3e34d9a49a5b382f54e74d36f22c6
Nonce: 44000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773901
Merkle Root: e9481096bc63e17a6002a830ac87ac65553557424f5608427ff28ab8541959d1
Hash: e07e3fb5267a0a4757c13fcd98a4b0facf6fb82f7d9f80c18cf6f54711e19d9d
Current Blockchain Height: 44
-----------------------------
------ New Block ------
Parent Hash: e07e3fb5267a0a4757c13fcd98a4b0facf6fb82f7d9f80c18cf6f54711e19d9d
Nonce: 45000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773901
Merkle Root: b3c185cb83140620e08cabf905ef5e6d910f9e9986b103539bb2c0c9d891b2a2
Hash: 9447a2c5cde93cbaeda0315707fd2148c3c64cba0e3cc103e3db124def53a467
Current Blockchain Height: 45
-----------------------------
------ New Block ------
Parent Hash: 9447a2c5cde93cbaeda0315707fd2148c3c64cba0e3cc103e3db124def53a467
Nonce: 46000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773901
Merkle Root: cbb9d751b2dfcc77e8058d0fb400103eae2145521abaf9e730898158c2e30fd2
Hash: 3f57f6150bad5cbd2a5d678e02e2d805d44175bfc7ad4a0ab7bc5264ececb0f5
Current Blockchain Height: 46
-----------------------------
------ New Block ------
Parent Hash: 3f57f6150bad5cbd2a5d678e02e2d805d44175bfc7ad4a0ab7bc5264ececb0f5
Nonce: 47000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773902
Merkle Root: a9f6e21663764d41484852014b81550bcbea834e05a36bdf16fec993f0b773ee
Hash: 4fb86f5a76c4286a832ebbe404f2fab2ce71365f4f14ce7f981c6b42dae4b110
Current Blockchain Height: 47
-----------------------------
------ New Block ------
Parent Hash: 4fb86f5a76c4286a832ebbe404f2fab2ce71365f4f14ce7f981c6b42dae4b110
Nonce: 48000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773902
Merkle Root: 9a703057165599c0fa12aa431bd8bc79cdf68abf1d50b82ea1b7d773f73b8bf9
Hash: 2bd4da3594ab89cb51f5e0ddd72c4af8ef9e52b31154812dc49d8804ea957a48
Current Blockchain Height: 48
-----------------------------
------ New Block ------
Parent Hash: 2bd4da3594ab89cb51f5e0ddd72c4af8ef9e52b31154812dc49d8804ea957a48
Nonce: 49000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773902
Merkle Root: 4e4c0faf096589ef6080e757ebfd39dbbe97b31e017a49e6933b0299bc835227
Hash: 0c08b65022524cad4033e6d0db320c7713ebef1f3de173760b2d6c98712c6828
Current Blockchain Height: 49
-----------------------------
------ New Block ------
Parent Hash: 0c08b65022524cad4033e6d0db320c7713ebef1f3de173760b2d6c98712c6828
Nonce: 50000
Difficulty: 0000000000000000000000000000000000000000
Timestamp: 1738773902
Merkle Root: ca928a58b7c32020f87d289547522f8eb36af28c208128f7ffafe95b2a4e326e
Hash: a35b819c990bbeb1265835f1acc90a417dd30cf2fb74ab3068f3e9f47b3d2079
Current Blockchain Height: 50
-----------------------------
Blockchain from Genesis to Tip:
Block Hash: cf97cc4aa82fa5bbb36153e13e3f01937358b281cfcd460b1b493176cbac872d
Block Hash: 58e157769bc49da04544134582b90be608bc7b025fdd213add2aa0126ea9527e
Block Hash: def241baee86ddac0a62ef3a00f134e1236747b6cf4214e2ec54271bcb3e70a7
Block Hash: 27bae4acf9122c4fca0d2549d1383480a62a40574e8633135c0b8e63a915152a
Block Hash: 2d3e784400b13f4e7f70b8d5ee0a9e8da73e87ef89cddcc04776cae86a320018
Block Hash: 1e2024aa21dc422cf21a9c744889e1232b6ecdb7ce74aa3a70493c49fc275ab4
Block Hash: 490df40a6bc984c3040def14bd064457b8f17e94ffd34ab2d1a6afaa16b1d628
Block Hash: e32f61780c070a701257cab2361039da52ae031fe5ca8f850abb94b19e89e0af
Block Hash: 74146897a5ed6e945f1f418357dde0da773172e481d827bdd67a785c2793902b
Block Hash: 56736ae540b204a2ddad29a676040c53d32623184c95381c004c4d1ee87ad4db
Block Hash: 71722720cb96762e65564114566d4ab6162e806f34de3f84fb66fc7fb50555e0
Block Hash: f64ef46bc2f88efcafe48f1f55872d0af6ec3e21028255d6fbcbe7c37530d750
Block Hash: b23c97e0f571c62a9bc85d3ccbbfa8f6abf7cb0e296bf1df2ea037b99d1954ad
Block Hash: bb894e66d835d7b34da2837f1682367be8627747790c2471220b651a54602402
Block Hash: c4f6395fc2c8dbd2dd3d4ad8320d02b0368c218bb1e08f508e95215109388bd0
Block Hash: 76bdb6b813d5472f0249474ca6ac5417d4b9e5c2a9b7159f622e17991685d1bd
Block Hash: 9c2b23ebefd1e75261b57a35222466c1226cc41ab21925d5da776559a62bd618
Block Hash: 0bd3b611af7de663141e661cd11a7084173cf7d26dbd097be56abe9e4001a45f
Block Hash: 88a33ecd765e19991b83b66a9412db44443666d3c393de040f4aa7897887527d
Block Hash: 982f9ef13e1be803e52c4235c94ef8dfa4071365961ed223a7e3c6d23a29f15a
Block Hash: 1238386f43a48ddeaa7c4958d85164eaa85ca17d1cb83e3a76deeadb4bcbc8a4
Block Hash: 5120ab0eb9fbb7d2c3c59d9ffc5359be3fc45d2f35d21c10bbf68af99012b43a
Block Hash: 2be51ebcd91cc81dfc069808327780b501620a0f7e09010c281fe9060b699570
Block Hash: 29eb874be1f7e170b549b4e6e550bfa0adac9b7c51d29003b53e966611d73b68
Block Hash: 651eb0dc11623a97d14822f3e0b183d76e32f9d810bf2b2ac02a09711c3a8f98
Block Hash: 0cf9309cc003c11fd901948e2a6aac4eae446865edade17937a048cfba3b7cf2
Block Hash: bb495d174d92799f9179e3a79a5a317941b6dd7a168e7de05cb18b3dda166b8e
Block Hash: fa69e1ac48fae941f4d71c02db8c606e0d8cf2da636d105f83ad3548b6c730d8
Block Hash: 4460cd5757cb151892f95f8aa5e7868fc7cd434903b2b2545e8dab83d1d67cbc
Block Hash: 3e4b68ac83a1081fdb63401eb21097aa35f94c805c630657c31b7d500003531b
Block Hash: 81cb631d4ad5df8ca4f5dc472b73845c02773561c1a8ff25fc0e9ca00251e21d
Block Hash: de74f401bdbce1c2b48157eaf3b8f6ff795ee8c498db013160f6137751faf1fd
Block Hash: 0634fc09df021872d0b3bf6b383730a51c7b49769c58b5511eab152f0a003e12
Block Hash: 140b85e0215039d5fd4733028ecc8d1839a039166244af3d8c9701a03eb0a064
Block Hash: 3e6b8f065447eb169b752ed39864a15b7c2de3d847358f8aebb85624c3643f42
Block Hash: 6dddb03982fc2fe8db82cfa4c85eca339f7a5343e02f8c5a34c7b33c8f70efb1
Block Hash: ebb164824c2f02ee3a44af226a9b2fcfc69002ae1aac1bf8061ea711ed39407c
Block Hash: abba0d11a93bd6361cd38b8a75986cce3617a80b5448f9a39ab460bbef6c07b3
Block Hash: 78a6995f921736ec400d283a73c280c595b37390ca2240d9b4513f87c2e8beb8
Block Hash: 10dad826abd55c5efd513c64ebb5e9018dc62b6cec6dabeee1e3bc301d8fe341
Block Hash: e87bd312645870a5ae3e1e5a23f5e507267365920e70f4d7018fe0c5934733c5
Block Hash: 60d699bcf742842a3ac4ae5b7aecbf9b170a2c9f18afc2247d500a6a38c98480
Block Hash: be0f4453cf34688fe7479b3d85c2671e04ae2a4f7db88fef4c6090cb2e696507
Block Hash: d4e598cb46ef2b954ada57524d6b454334b3e34d9a49a5b382f54e74d36f22c6
Block Hash: e07e3fb5267a0a4757c13fcd98a4b0facf6fb82f7d9f80c18cf6f54711e19d9d
Block Hash: 9447a2c5cde93cbaeda0315707fd2148c3c64cba0e3cc103e3db124def53a467
Block Hash: 3f57f6150bad5cbd2a5d678e02e2d805d44175bfc7ad4a0ab7bc5264ececb0f5
Block Hash: 4fb86f5a76c4286a832ebbe404f2fab2ce71365f4f14ce7f981c6b42dae4b110
Block Hash: 2bd4da3594ab89cb51f5e0ddd72c4af8ef9e52b31154812dc49d8804ea957a48
Block Hash: 0c08b65022524cad4033e6d0db320c7713ebef1f3de173760b2d6c98712c6828
Block Hash: a35b819c990bbeb1265835f1acc90a417dd30cf2fb74ab3068f3e9f47b3d2079

Blockchain from Tip to Genesis:
Block Hash: a35b819c990bbeb1265835f1acc90a417dd30cf2fb74ab3068f3e9f47b3d2079
Block Hash: 0c08b65022524cad4033e6d0db320c7713ebef1f3de173760b2d6c98712c6828
Block Hash: 2bd4da3594ab89cb51f5e0ddd72c4af8ef9e52b31154812dc49d8804ea957a48
Block Hash: 4fb86f5a76c4286a832ebbe404f2fab2ce71365f4f14ce7f981c6b42dae4b110
Block Hash: 3f57f6150bad5cbd2a5d678e02e2d805d44175bfc7ad4a0ab7bc5264ececb0f5
Block Hash: 9447a2c5cde93cbaeda0315707fd2148c3c64cba0e3cc103e3db124def53a467
Block Hash: e07e3fb5267a0a4757c13fcd98a4b0facf6fb82f7d9f80c18cf6f54711e19d9d
Block Hash: d4e598cb46ef2b954ada57524d6b454334b3e34d9a49a5b382f54e74d36f22c6
Block Hash: be0f4453cf34688fe7479b3d85c2671e04ae2a4f7db88fef4c6090cb2e696507
Block Hash: 60d699bcf742842a3ac4ae5b7aecbf9b170a2c9f18afc2247d500a6a38c98480
Block Hash: e87bd312645870a5ae3e1e5a23f5e507267365920e70f4d7018fe0c5934733c5
Block Hash: 10dad826abd55c5efd513c64ebb5e9018dc62b6cec6dabeee1e3bc301d8fe341
Block Hash: 78a6995f921736ec400d283a73c280c595b37390ca2240d9b4513f87c2e8beb8
Block Hash: abba0d11a93bd6361cd38b8a75986cce3617a80b5448f9a39ab460bbef6c07b3
Block Hash: ebb164824c2f02ee3a44af226a9b2fcfc69002ae1aac1bf8061ea711ed39407c
Block Hash: 6dddb03982fc2fe8db82cfa4c85eca339f7a5343e02f8c5a34c7b33c8f70efb1
Block Hash: 3e6b8f065447eb169b752ed39864a15b7c2de3d847358f8aebb85624c3643f42
Block Hash: 140b85e0215039d5fd4733028ecc8d1839a039166244af3d8c9701a03eb0a064
Block Hash: 0634fc09df021872d0b3bf6b383730a51c7b49769c58b5511eab152f0a003e12
Block Hash: de74f401bdbce1c2b48157eaf3b8f6ff795ee8c498db013160f6137751faf1fd
Block Hash: 81cb631d4ad5df8ca4f5dc472b73845c02773561c1a8ff25fc0e9ca00251e21d
Block Hash: 3e4b68ac83a1081fdb63401eb21097aa35f94c805c630657c31b7d500003531b
Block Hash: 4460cd5757cb151892f95f8aa5e7868fc7cd434903b2b2545e8dab83d1d67cbc
Block Hash: fa69e1ac48fae941f4d71c02db8c606e0d8cf2da636d105f83ad3548b6c730d8
Block Hash: bb495d174d92799f9179e3a79a5a317941b6dd7a168e7de05cb18b3dda166b8e
Block Hash: 0cf9309cc003c11fd901948e2a6aac4eae446865edade17937a048cfba3b7cf2
Block Hash: 651eb0dc11623a97d14822f3e0b183d76e32f9d810bf2b2ac02a09711c3a8f98
Block Hash: 29eb874be1f7e170b549b4e6e550bfa0adac9b7c51d29003b53e966611d73b68
Block Hash: 2be51ebcd91cc81dfc069808327780b501620a0f7e09010c281fe9060b699570
Block Hash: 5120ab0eb9fbb7d2c3c59d9ffc5359be3fc45d2f35d21c10bbf68af99012b43a
Block Hash: 1238386f43a48ddeaa7c4958d85164eaa85ca17d1cb83e3a76deeadb4bcbc8a4
Block Hash: 982f9ef13e1be803e52c4235c94ef8dfa4071365961ed223a7e3c6d23a29f15a
Block Hash: 88a33ecd765e19991b83b66a9412db44443666d3c393de040f4aa7897887527d
Block Hash: 0bd3b611af7de663141e661cd11a7084173cf7d26dbd097be56abe9e4001a45f
Block Hash: 9c2b23ebefd1e75261b57a35222466c1226cc41ab21925d5da776559a62bd618
Block Hash: 76bdb6b813d5472f0249474ca6ac5417d4b9e5c2a9b7159f622e17991685d1bd
Block Hash: c4f6395fc2c8dbd2dd3d4ad8320d02b0368c218bb1e08f508e95215109388bd0
Block Hash: bb894e66d835d7b34da2837f1682367be8627747790c2471220b651a54602402
Block Hash: b23c97e0f571c62a9bc85d3ccbbfa8f6abf7cb0e296bf1df2ea037b99d1954ad
Block Hash: f64ef46bc2f88efcafe48f1f55872d0af6ec3e21028255d6fbcbe7c37530d750
Block Hash: 71722720cb96762e65564114566d4ab6162e806f34de3f84fb66fc7fb50555e0
Block Hash: 56736ae540b204a2ddad29a676040c53d32623184c95381c004c4d1ee87ad4db
Block Hash: 74146897a5ed6e945f1f418357dde0da773172e481d827bdd67a785c2793902b
Block Hash: e32f61780c070a701257cab2361039da52ae031fe5ca8f850abb94b19e89e0af
Block Hash: 490df40a6bc984c3040def14bd064457b8f17e94ffd34ab2d1a6afaa16b1d628
Block Hash: 1e2024aa21dc422cf21a9c744889e1232b6ecdb7ce74aa3a70493c49fc275ab4
Block Hash: 2d3e784400b13f4e7f70b8d5ee0a9e8da73e87ef89cddcc04776cae86a320018
Block Hash: 27bae4acf9122c4fca0d2549d1383480a62a40574e8633135c0b8e63a915152a
Block Hash: def241baee86ddac0a62ef3a00f134e1236747b6cf4214e2ec54271bcb3e70a7
Block Hash: 58e157769bc49da04544134582b90be608bc7b025fdd213add2aa0126ea9527e
Block Hash: cf97cc4aa82fa5bbb36153e13e3f01937358b281cfcd460b1b493176cbac872d
*/