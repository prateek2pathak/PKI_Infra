#include <cryptopp/rsa.h>
#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <fstream>

using namespace CryptoPP;

int main(int argc, char* argv[]) {
    if (argc != 4) {
        cerr << "Usage: IssueCertificate <user email> <CA_Priv.bin> <User_Pub.bin>" << endl;
        return 1;
    }

    string userEmail = argv[1];
    string issuer = "IIITA";

    AutoSeededRandomPool rng;

    try {
        // Load CA private key
        DSA::PrivateKey caPrivKey;
        FileSource privFile(argv[2], true);
        caPrivKey.Load(privFile);

        // Load User public key
        RSA::PublicKey userPubKey;
        FileSource pubFile(argv[3], true);
        userPubKey.Load(pubFile);

        // Debug: Confirm key loading
        cout << "CA private key and User public key loaded successfully." << endl;

        // Continue with certificate generation...

        // Create certificate data
        string certificateData = "Issuer Name: " + issuer + "\n";
        certificateData += "Subject ID: " + userEmail + "\n";
        certificateData += "Validity:\n";
        certificateData += "  NotBefore: Sun, 16 Jun 2024\n";
        certificateData += "  NotAfter: Sun, 22 Jun 2026\n";
        certificateData += "Signature Algorithm: DSA\n";

        // Convert the public key to string (just for demonstration purposes)
        HexEncoder encoder(new StringSink(certificateData));
        userPubKey.Save(encoder);
        certificateData += "\n";

        // Generate a hash of the certificate data
        SHA256 hash;
        string digest;
        StringSource(certificateData, true, new HashFilter(hash, new StringSink(digest)));

        // Sign the hash
        DSA::Signer signer(caPrivKey);
        string signature;
        StringSource(digest, true, new SignerFilter(rng, signer, new StringSink(signature)));

        // Append the signature to the certificate data
        string certificate = certificateData + "Signature: " + signature + "\n";

        // Save the certificate
        ofstream certFile("certificate.bin", ios::binary);
        certFile.write(certificate.c_str(), certificate.size());
        certFile.close();

        cout << "Certificate generated successfully." << endl;

    } catch (const Exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}

