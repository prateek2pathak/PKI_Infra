#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool rng;

    // Generate the DSA key pair
    DSA::PrivateKey privateKey;
    DSA::PublicKey publicKey;
    privateKey.GenerateRandomWithKeySize(rng, 2048);
    privateKey.MakePublicKey(publicKey);

    // Save the keys
    FileSink pubFile("CA_Pub.bin", true);
    publicKey.Save(pubFile);
    
    FileSink privFile("CA_Priv.bin", true);
    privateKey.Save(privFile);

    return 0;
}

