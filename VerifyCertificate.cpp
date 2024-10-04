#include <cryptopp/rsa.h>
#include <cryptopp/dsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <fstream>
#include <string>

using namespace CryptoPP;

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "Usage: VerifyCertificate <certificate.bin> <CA_Pub.bin>" << endl;
        return 1;
    }

    try {
        // Load CA public key
        DSA::PublicKey caPubKey;
        FileSource pubFile(argv[2], true);
        caPubKey.Load(pubFile);

        // Load the certificate
        ifstream certFile(argv[1], ios::binary);
        string certificate((istreambuf_iterator<char>(certFile)), istreambuf_iterator<char>());
        certFile.close();

        // Extract the signature from the certificate
        string::size_type sigPos = certificate.find("Signature: ");
        if (sigPos == string::npos) {
            cerr << "Error: Signature not found in certificate." << endl;
            return 1;
        }
        string certData = certificate.substr(0, sigPos);
        string signature = certificate.substr(sigPos + string("Signature: ").length());

        // Hash the certificate data (excluding the signature)
        SHA256 hash;
        string digest;
        StringSource(certData, true, new HashFilter(hash, new StringSink(digest)));

        // Verify the signature
        DSA::Verifier verifier(caPubKey);
        bool result = verifier.VerifyMessage((const byte*)digest.data(), digest.size(), (const byte*)signature.data(), signature.size());

        // Debug: Output intermediate values
        cout << "Certificate Data:\n" << certData << endl;
        cout << "Signature (Hex): ";
        StringSource(signature, true, new HexEncoder(new FileSink(cout)));
        cout << endl;
        cout << "Hash (Hex): ";
        StringSource(digest, true, new HexEncoder(new FileSink(cout)));
        cout << endl;

        // Output the result
        if (result) {
            cout << "Success" << endl;
        } else {
            cout << "Failure" << endl;
        }

    } catch (const Exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}

