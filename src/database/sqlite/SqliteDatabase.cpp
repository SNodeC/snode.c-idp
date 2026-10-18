/*
 * SNode.C - A Slim Toolkit for Network Communication
 * Copyright (C) Volker Christian <me@vchrist.at>
 *               2020, 2021, 2022, 2023, 2024, 2025
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "database/sqlite/SqliteDatabase.h"

#include <sqlite3.h>
#include <stdexcept>
#include <string>

namespace snodec::database::sqlite {

    // ========================================================================
    // Row
    // ========================================================================

    SqliteDatabase::Row::Row(sqlite3_stmt* stmt)
        : stmt_(stmt) {
    }


    int SqliteDatabase::Row::columnCount() const {
        return sqlite3_column_count(stmt_);
    }

    std::string SqliteDatabase::Row::get(int index) const {
        // sqlite3_column_text returns NULL for SQL NULL or if index is OOB.
        const unsigned char* raw = sqlite3_column_text(stmt_, index);
        return raw ? reinterpret_cast<const char*>(raw) : "";
    }

    std::string SqliteDatabase::Row::get(const std::string& name) const {
        const int count = sqlite3_column_count(stmt_);
        for (int i = 0; i < count; ++i) {
            const char* colName = sqlite3_column_name(stmt_, i);
            if (colName && name == colName) {
                return get(i);
            }
        }
        return "";
    }

    bool SqliteDatabase::Row::isNull(int index) const {
        return sqlite3_column_type(stmt_, index) == SQLITE_NULL;
    }

    // ========================================================================
    // SqliteDatabase — Construction / Destruction
    // ========================================================================

    SqliteDatabase::SqliteDatabase(const std::string& filePath)
        : db_(nullptr) {
        // SQLITE_OPEN_CREATE  – create if it doesn't exist.
        // SQLITE_OPEN_READWRITE – allow reads and writes.
        // SQLITE_OPEN_FULLMUTEX – serialised threading mode (safe default).
        const int rc = sqlite3_open_v2(filePath.c_str(),
                                       &db_,
                                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                                       nullptr);
        if (rc != SQLITE_OK) {
            const std::string msg = db_ ? sqlite3_errmsg(db_) : "unknown error";
            sqlite3_close(db_);
            db_ = nullptr;
            throw std::runtime_error("SqliteDatabase: cannot open '" + filePath + "': " + msg);
        }

        // Enable WAL for better concurrent-read performance.
        sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
        // Enforce foreign-key constraints.
        sqlite3_exec(db_, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
        // Reasonable busy timeout: 5 s.
        sqlite3_busy_timeout(db_, 5000);
    }

    SqliteDatabase::~SqliteDatabase() {
        if (db_ != nullptr) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

    // ========================================================================
    // Schema Initialisation
    // ========================================================================

    void SqliteDatabase::initSchema() {
        static const char* SCHEMA = R"(
            -- Users table
            CREATE TABLE IF NOT EXISTS user (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                username         TEXT    NOT NULL UNIQUE,
                email            TEXT    NOT NULL UNIQUE,
                password_hash    TEXT    NOT NULL,
                password_salt    TEXT    NOT NULL,
                totp_secret      TEXT    DEFAULT NULL,
                totp_enabled     INTEGER DEFAULT 0,
                created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            -- Password reset tokens
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                token       TEXT    NOT NULL UNIQUE,
                user_id     INTEGER NOT NULL,
                expires_at  DATETIME NOT NULL,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE
            );

            -- Index for fast reset-token lookup
            CREATE INDEX IF NOT EXISTS idx_reset_token
                ON password_reset_tokens (token);
        )";

        char* errmsg = nullptr;
        const int rc = sqlite3_exec(db_, SCHEMA, nullptr, nullptr, &errmsg);
        if (rc != SQLITE_OK) {
            std::string msg = errmsg ? errmsg : "unknown error";
            sqlite3_free(errmsg);
            throw std::runtime_error("SqliteDatabase::initSchema failed: " + msg);
        }
        int version = 0;
        query("PRAGMA user_version", [&](const Row& row) {
            version = std::stoi(row.get(0));
        });
        if (version < 2) {
            if (!exec("BEGIN IMMEDIATE")) {
                throw std::runtime_error("Cannot start authentication migration");
            }
            try {
                auto sql = [this](const std::string& statement) {
                    if (!exec(statement)) {
                        throw std::runtime_error("Authentication migration failed");
                    }
                };
                auto column = [this, &sql](const std::string& table, const std::string& name, const std::string& definition) {
                    bool exists = false;
                    query("PRAGMA table_info(" + table + ")", [&](const Row& row) {
                        exists = exists || row.get(1) == name;
                    });
                    if (!exists) {
                        sql("ALTER TABLE " + table + " ADD COLUMN " + name + " " + definition);
                    }
                };
                column("user", "activated", "INTEGER NOT NULL DEFAULT 1");
                column("password_reset_tokens", "used", "INTEGER NOT NULL DEFAULT 0");
                sql("DROP TABLE IF EXISTS refresh_token");
                sql("DROP TABLE IF EXISTS auth_code");
                sql("DROP TABLE IF EXISTS session");
                sql("CREATE TABLE session(id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE NOT NULL, user_id INTEGER NOT NULL "
                    "REFERENCES user(id) ON DELETE CASCADE, mfa_verified INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL)");
                sql("CREATE TABLE auth_flow(token_hash TEXT PRIMARY KEY, context TEXT NOT NULL, expires_at INTEGER NOT NULL)");
                sql("CREATE TABLE auth_code(code TEXT PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES session(id) ON DELETE CASCADE, "
                    "context TEXT NOT NULL, expires_at INTEGER NOT NULL)");
                sql("CREATE TABLE refresh_token(token_hash TEXT PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES session(id) ON DELETE "
                    "CASCADE, context TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL)");
                sql("CREATE TABLE federated_identity(provider TEXT NOT NULL, subject TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES "
                    "user(id) ON DELETE CASCADE, PRIMARY KEY(provider,subject))");
                sql("CREATE TRIGGER revoke_account_credentials AFTER UPDATE OF password_hash,totp_enabled,totp_secret ON user BEGIN DELETE "
                    "FROM session WHERE user_id=NEW.id; DELETE FROM auth_flow WHERE json_extract(context,'$.user_id')=CAST(NEW.id AS "
                    "TEXT); DELETE FROM password_reset_tokens WHERE user_id=NEW.id; END");
                sql("CREATE TRIGGER revoke_deleted_flows AFTER DELETE ON user BEGIN DELETE FROM auth_flow WHERE "
                    "json_extract(context,'$.user_id')=CAST(OLD.id AS TEXT); END");
                sql("DELETE FROM password_reset_tokens");
                sql("PRAGMA user_version=2");
                sql("COMMIT");
            } catch (...) {
                exec("ROLLBACK");
                throw;
            }
        }
    }

    // ========================================================================
    // Internal helper: prepare + bind
    // ========================================================================

    sqlite3_stmt* SqliteDatabase::prepare(const std::string& sql,
                                          const std::vector<std::string>& params,
                                          std::string* errmsg) {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            if (errmsg) {
                *errmsg = sqlite3_errmsg(db_);
            }
            return nullptr;
        }

        // Bind parameters positionally (1-based in SQLite API).
        for (int i = 0; i < static_cast<int>(params.size()); ++i) {
            rc = sqlite3_bind_text(stmt,
                                   i + 1,
                                   params[static_cast<size_t>(i)].c_str(),
                                   -1,
                                   SQLITE_TRANSIENT);
            if (rc != SQLITE_OK) {
                if (errmsg) {
                    *errmsg = sqlite3_errmsg(db_);
                }
                sqlite3_finalize(stmt);
                return nullptr;
            }
        }

        return stmt;
    }

    // ========================================================================
    // exec – run a DML/DDL statement (no result rows expected)
    // ========================================================================

    bool SqliteDatabase::exec(const std::string& sql,
                               const std::vector<std::string>& params,
                               std::string* errmsg) {
        sqlite3_stmt* stmt = prepare(sql, params, errmsg);
        if (stmt == nullptr) {
            return false;
        }

        const int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            if (errmsg) {
                *errmsg = sqlite3_errmsg(db_);
            }
            return false;
        }
        return true;
    }

    // ========================================================================
    // query – run a SELECT and invoke callback for every row
    // ========================================================================

    bool SqliteDatabase::query(const std::string& sql,
                               const std::vector<std::string>& params,
                               const RowCallback& callback,
                               std::string* errmsg) {
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(prepare(sql, params, errmsg), sqlite3_finalize);
        int rc = SQLITE_ERROR;
        if (stmt) {
            while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
                Row row(stmt.get());
                callback(row);
            }
            if (rc != SQLITE_DONE && errmsg) {
                *errmsg = sqlite3_errmsg(db_);
            }
        }
        return rc == SQLITE_DONE;
    }

    bool SqliteDatabase::query(const std::string& sql,
                                const RowCallback& callback,
                                std::string* errmsg) {
        return query(sql, {}, callback, errmsg);
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    int64_t SqliteDatabase::lastInsertRowid() const {
        return sqlite3_last_insert_rowid(db_);
    }

    int SqliteDatabase::changedRows() const {
        return sqlite3_changes(db_);
    }

} // namespace snodec::database::sqlite
