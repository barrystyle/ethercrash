//! ethercrash simulator
//! barrystyle 23052022

#include <math.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#include <openssl/hmac.h>
#include <openssl/sha.h>

unsigned char *mx_hmac_sha256 (const void *key, int keylen,
                              const unsigned char *data, int datalen,
                              unsigned char *result, unsigned int *resultlen) {
    return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}

bool divisible(std::string& hash, unsigned int mod)
{
    char hexslice[6];
    memset(hexslice, 0, sizeof(hexslice));

    unsigned int val = 0;
    unsigned int o = hash.size() % 4;
    for (unsigned int i = o > 0 ? o - 4 : 0; i < hash.size(); i += 4) {
        sprintf(hexslice, "%s", hash.substr(i, i+4).c_str());
        std::string s = std::string(hexslice);
        val = ((val << 16) + std::stoll(s, nullptr, 16) % mod);
    }

    return (val == 0);
}

std::string gen_gamehash(std::string& server_seed)
{
    char buffer[128];
    memset(buffer, 0, sizeof(buffer));
    int buflen = server_seed.size();
    sprintf(buffer, "%s", server_seed.c_str());

    char hash[32];
    memset(hash, 0, sizeof(hash));
    SHA256((const unsigned char*)buffer, buflen, (unsigned char*)hash);

    char hashhex[64+1];
    memset(hashhex, 0, sizeof(hashhex));
    for (int i = 0; i < 32; i++) {
        sprintf(hashhex + (i * 2), "%02hhx", hash[i]);
    }

    return std::string(hashhex);
}

std::string hmac_hashfunction(std::string& key, std::string& v)
{
    char keyhex[64+1];
    memset(keyhex, 0, sizeof(keyhex));
    int keylen = key.size();
    sprintf(keyhex, "%s", key.c_str());

    char vhex[128];
    memset(vhex, 0, sizeof(vhex));
    int vlen = v.size();
    sprintf(vhex, "%s", v.c_str());

    unsigned int resultlen;
    unsigned char resultbin[32];
    memset(resultbin, 0, sizeof(resultbin));
    mx_hmac_sha256((const void *)keyhex, keylen, (unsigned char *)vhex, vlen, (unsigned char *)resultbin, &resultlen);

    char resulthex[64+1];
    memset(resulthex, 0, sizeof(resulthex));
    for (int i = 0; i < 32; i++) {
        sprintf(resulthex + (i * 2), "%02hhx", resultbin[i]);
    }

    return std::string(resulthex);
}

void gen_crashpoint(std::string& server_seed, double& crash)
{
    std::string vseed = "0xd8b8a187d5865a733680b4bf4d612afec9c6829285d77f438cd70695fb946801";
    std::string hash = hmac_hashfunction(server_seed, vseed);

    if (divisible(hash, 101)) {
        crash = 0;
        return;
    }

    char hexslice[16];
    memset(hexslice, 0, sizeof(hexslice));
    sprintf(hexslice, "%s", hash.substr(0,52/4).c_str());
    std::string s = std::string(hexslice);
    double h = std::stoll(s, nullptr, 16);
    double e = std::pow(2, 52);

    crash = (floor((100 * e - h) / (e - h)) / 100);
}

int main(int argc, char** argv)
{
    if (argc < 6) {
        printf("\nethercrash requires 5 arguments\n");
        printf("./ethercrash balance betamount estcrash games hash\n");
        printf("\n");
        printf("example:\n");
        printf("./ethercrash 50000 5000 1.29 25 25dbaf31c4fbef123dbcea4da583d23cea8fb827c1dd9ab1f153fe9ab880eb1e\n\n");
        return 0;
    }

    double balance = 15000;
    double betamount = 1000;
    double estcrash = 5;
    unsigned int games = 500;
    std::string hash = "25dbaf31c4fbef123dbcea4da583d23cea8fb827c1dd9ab1f153fe9ab880eb1e";

    std::vector<std::pair<std::string, double>> prevgames;

    std::string gamehash, lasthash;
    gamehash.clear();
    lasthash.clear();
    double gamecrash = 0;

    //! calculate the game results
    for (unsigned int i = 0; i < games; i++) {
        if (lasthash.empty()) {
            gamehash = hash;
        } else {
            gamehash = gen_gamehash(lasthash);
        }
        gen_crashpoint(gamehash, gamecrash);
        prevgames.push_back(std::make_pair(gamehash, gamecrash));
        lasthash = gamehash;
    }

    //! reverse and play them back
    for (unsigned int i = games - 1; i; i--) {
        balance = balance - betamount;
        if (estcrash < prevgames[i].second)
            balance = balance + betamount + (betamount * estcrash);
        if (balance <= 0)
            return 0;
        printf("%s - %.2f (balance: %.0f)\n", prevgames[i].first.c_str(), prevgames[i].second, balance);
    }

    return 0;
}
