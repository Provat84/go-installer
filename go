#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

void signDocument(const std::string& xmlData) {
    FILE* privKeyFile = fopen("private_key.pem", "r");
    RSA* rsa = PEM_read_RSAPrivateKey(privKeyFile, nullptr, nullptr, nullptr);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(xmlData.c_str()), xmlData.size(), hash);

    unsigned char signature[RSA_size(rsa)];
    unsigned int sigLen;
    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &sigLen, rsa);

    // Attach the signature to XML and send
    fclose(privKeyFile);
}
