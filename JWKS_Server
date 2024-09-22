#include <iostream>
#include <string>
#include <map>
#include <ctime>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <httplib.h>
#include <jwt-cpp/jwt.h>

#define PORT 8080

// Structure for Key information
struct KeyInfo {
    std::string kid;
    std::string publicKey;
    std::string privateKey;
    time_t expiry;
};

// Map to hold the keys and their metadata
std::map<std::string, KeyInfo> keyStore;

// Generate an RSA key pair and return the keys as strings
KeyInfo generateRSAKeyPair() {
    int bits = 2048;
    unsigned long e = RSA_F4;
    RSA *rsa = RSA_generate_key(bits, e, nullptr, nullptr);
    
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    PEM_write_bio_RSA_PUBKEY(pub, rsa);

    char *priKey, *pubKey;
    size_t priLen = BIO_pending(pri);
    size_t pubLen = BIO_pending(pub);

    priKey = (char *)malloc(priLen + 1);
    pubKey = (char *)malloc(pubLen + 1);

    BIO_read(pri, priKey, priLen);
    BIO_read(pub, pubKey, pubLen);

    priKey[priLen] = '\0';
    pubKey[pubLen] = '\0';

    std::string privateKey(priKey);
    std::string publicKey(pubKey);

    free(priKey);
    free(pubKey);
    BIO_free_all(pri);
    BIO_free_all(pub);
    RSA_free(rsa);

    KeyInfo keyInfo;
    keyInfo.kid = std::to_string(time(0)); // Use timestamp as kid
    keyInfo.publicKey = publicKey;
    keyInfo.privateKey = privateKey;
    keyInfo.expiry = time(0) + 3600; // Key expiry set to 1 hour

    return keyInfo;
}

// Handler for /.well-known/jwks.json
void handleJWKS(const httplib::Request &req, httplib::Response &res) {
    std::string jwks = R"({"keys": [)";
    bool first = true;
    time_t now = time(0);

    for (const auto &pair : keyStore) {
        const KeyInfo &key = pair.second;
        if (key.expiry > now) { // Only return unexpired keys
            if (!first) jwks += ",";
            jwks += R"({"kid": ")" + key.kid + R"(", "kty": "RSA", "alg": "RS256", "use": "sig", "n": ")" + key.publicKey + R"("})";
            first = false;
        }
    }

    jwks += "]}";
    res.set_content(jwks, "application/json");
}

// Handler for /auth
void handleAuth(const httplib::Request &req, httplib::Response &res) {
    time_t now = time(0);
    bool useExpired = req.has_param("expired");

    KeyInfo key;
    if (useExpired) {
        // Get an expired key if any
        for (const auto &pair : keyStore) {
            if (pair.second.expiry <= now) {
                key = pair.second;
                break;
            }
        }
    } 
    
    else {
        // Get the latest unexpired key
        for (const auto &pair : keyStore) {
            if (pair.second.expiry > now) {
                key = pair.second;
                break;
            }
        }
    }

    if (!key.kid.empty()) {
        // Create JWT with key
        auto token = jwt::create()
                         .set_issuer("auth_server")
                         .set_type("JWT")
                         .set_issued_at(now)
                         .set_expires_at(now + 3600)
                         .set_payload_claim("sub", jwt::claim(std::string("user")))
                         .sign(jwt::algorithm::rs256(key.publicKey, key.privateKey, "", ""));

        res.set_content(token, "text/plain");
    } 

    else {
        res.status = 404;
        res.set_content("No valid keys found.", "text/plain");
    }
}

int main() {
    // Generate initial RSA key pairs and add them to the key store
    keyStore["key1"] = generateRSAKeyPair();
    keyStore["key2"] = generateRSAKeyPair(); // Simulating multiple keys

    httplib::Server svr;

    svr.Get("/.well-known/jwks.json", handleJWKS);
    svr.Post("/auth", handleAuth);

    std::cout << "Server started on port " << PORT << "..." << std::endl;
    svr.listen("0.0.0.0", PORT);

    return 0;
}
