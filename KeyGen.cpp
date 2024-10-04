#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool rng;

    // Generate the RSA key pair
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    privateKey.GenerateRandomWithKeySize(rng, 1024);
    publicKey.AssignFrom(privateKey);

    // Save the keys
    FileSink pubFile("User_Pub.bin", true);
    publicKey.Save(pubFile);
    
    FileSink privFile("User_Priv.bin", true);
    privateKey.Save(privFile);

    return 0;
}

