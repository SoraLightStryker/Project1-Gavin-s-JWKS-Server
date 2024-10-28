#include <iostream>
#include <string>
#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sqlite3.h>
#include <chrono>

// Convert BIGNUM to a raw string for encoding
std::string bignum_to_raw_string(const BIGNUM* bn) {
    int bn_size = BN_num_bytes(bn);
    std::string raw(bn_size, 0);
    BN_bn2bin(bn, reinterpret_cast<unsigned char*>(&raw[0]));
    return raw;
}

// Base64 URL encode a string
std::string base64_url_encode(const std::string& data) {
    static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string ret;
    int i = 0, j = 0;
    unsigned char char_array_3[3], char_array_4[4];

    for (size_t n = 0; n < data.size(); n++) {
        char_array_3[i++] = data[n];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) char_array_3[j] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        for (j = 0; j < i + 1; j++) ret += base64_chars[char_array_4[j]];
    }
    std::replace(ret.begin(), ret.end(), '+', '-');
    std::replace(ret.begin(), ret.end(), '/', '_');
    ret.erase(std::remove(ret.begin(), ret.end(), '='), ret.end());
    return ret;
}

// Database setup
void initialize_database() {
    sqlite3* db;
    int rc = sqlite3_open("totally_not_my_privateKeys.db", &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    const char* create_table_sql = R"(
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            exp INTEGER NOT NULL
        );
    )";

    rc = sqlite3_exec(db, create_table_sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        std::cerr << "Can't create table: " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_close(db);
}

// Store key in database
void store_key_in_db(const std::string& priv_key, int expiration) {
    sqlite3* db;
    sqlite3_open("totally_not_my_privateKeys.db", &db);

    const char* insert_sql = "INSERT INTO keys (key, exp) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, priv_key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, expiration);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

// Retrieve a key from database based on expiration status
std::string retrieve_key_from_db(bool expired) {
    sqlite3* db;
    sqlite3_open("totally_not_my_privateKeys.db", &db);

    const char* select_sql = expired ?
        "SELECT key FROM keys WHERE exp < strftime('%s', 'now') LIMIT 1;" :
        "SELECT key FROM keys WHERE exp >= strftime('%s', 'now') LIMIT 1;";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, select_sql, -1, &stmt, 0);

    std::string key;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return key;
}

// Server main function
int main() {
    // Initialize database
    initialize_database();

    // Generate RSA key pair
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    // Extract private key as PEM for storage
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    char* priv_key_data = NULL;
    long priv_key_len = BIO_get_mem_data(bio, &priv_key_data);
    std::string priv_key(priv_key_data, priv_key_len);
    BIO_free(bio);

    // Store the key in DB with an expiration of 1 hour from now
    int expiration_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::hours(1));
    store_key_in_db(priv_key, expiration_time);

    // Start HTTP server
    httplib::Server svr;

    svr.Post("/auth", [&](const httplib::Request& req, httplib::Response& res) {
        bool expired = req.has_param("expired") && req.get_param_value("expired") == "true";
        std::string priv_key = retrieve_key_from_db(expired);

        if (priv_key.empty()) {
            res.status = 404;
            res.set_content("No suitable key found", "text/plain");
            return;
        }

        // Create JWT token
        auto now = std::chrono::system_clock::now();
        auto token = jwt::create()
            .set_issuer("auth0")
            .set_type("JWT")
            .set_payload_claim("sample", jwt::claim(std::string("test")))
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(expired ? now - std::chrono::seconds{ 1 } : now + std::chrono::hours{ 24 })
            .sign(jwt::algorithm::rs256(priv_key, priv_key));

        res.set_content(token, "text/plain");
        });

    svr.Get("/.well-known/jwks.json", [&](const httplib::Request&, httplib::Response& res) {
        std::string jwks = "{\"keys\": [";

        sqlite3* db;
        sqlite3_open("totally_not_my_privateKeys.db", &db);
        const char* select_sql = "SELECT key FROM keys WHERE exp >= strftime('%s', 'now');";
        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db, select_sql, -1, &stmt, 0);

        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) jwks += ", ";
            std::string pub_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            jwks += R"({"kty":"RSA","use":"sig","alg":"RS256","n":")" + base64_url_encode(pub_key) + R"("})";
            first = false;
        }

        jwks += "]}";
        sqlite3_finalize(stmt);
        sqlite3_close(db);

        res.set_content(jwks, "application/json");
        });

    svr.listen("127.0.0.1", 8080);

    EVP_PKEY_free(pkey);
    return 0;
}

