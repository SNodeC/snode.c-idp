#pragma once
#include "Security.h"
#include "database/sqlite/SqliteDatabase.h"

namespace snodec::auth {
    class AuthStore {
    public:
        explicit AuthStore(database::sqlite::SqliteDatabase& db, Json clients);
        Json authorization(const Json& input) const;
        std::string begin(const Json& context);
        Json flow(const std::string& browserToken);
        Json formFlow(const std::string& browserToken, const std::string& transaction);
        void save(const std::string& browserToken, const Json& context);
        Json complete(const std::string& browserToken, const std::string& userId, bool mfaVerified, bool enrollment = false);
        Json redeem(const Json& parameters);
        Json session(const std::string& cookie);
        bool active(const std::string& id, const std::string& userId, bool mfa);
        void migrateTotp(const std::string& keyPath);
        void requestReset(const std::string& email, const std::function<void(const std::string&, const std::string&)>& deliver);
        void resetPassword(const std::string& token, const std::string& passwordHash);
        void execute(const std::string& sql, const std::vector<std::string>& args = {});

    private:
        database::sqlite::SqliteDatabase& db_;
        Json clients_;
    };
} // namespace snodec::auth
