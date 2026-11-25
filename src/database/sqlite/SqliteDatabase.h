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

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// Forward-declare the SQLite handle to avoid exposing sqlite3.h in headers.
struct sqlite3;
struct sqlite3_stmt;

namespace snodec::database::sqlite {

    /**
     * @brief A lightweight, RAII-based synchronous SQLite wrapper.
     *
     * Designed for embedded/IoT deployments (OpenWrt routers) where MariaDB
     * is too heavy. Uses prepared statements for all queries to prevent SQL
     * injection. Operates in WAL mode for improved concurrent read performance.
     *
     * Thread-safety: Not thread-safe on its own. SNode.C runs on a single
     * event-loop thread, so no locking is required in normal usage.
     */
    class SqliteDatabase {
    public:
        /**
         * @brief Represents a single result row from a query.
         *
         * Column values are exposed as strings (SQLite stores everything
         * as text, real, integer, or blob; we normalise to string here).
         * Access by zero-based column index or column name.
         */
        class Row {
        public:
            explicit Row(sqlite3_stmt* stmt);

            /// Number of columns in this row.
            int columnCount() const;

            /// Value of column at @p index as a string ("" if NULL).
            std::string get(int index) const;

            /// Value of column named @p name as a string ("" if NULL).
            std::string get(const std::string& name) const;

            /// True if column at @p index is SQL NULL.
            bool isNull(int index) const;

        private:
            sqlite3_stmt* stmt_; // non-owning, valid only during the callback
        };

        using RowCallback = std::function<void(const Row&)>;

        // ----------------------------------------------------------------
        // Construction / Destruction
        // ----------------------------------------------------------------

        /**
         * @brief Open (or create) the SQLite database at @p filePath.
         * @throws std::runtime_error if the database cannot be opened.
         */
        explicit SqliteDatabase(const std::string& filePath);

        ~SqliteDatabase();

        // Non-copyable, non-movable (owns the sqlite3* handle).
        SqliteDatabase(const SqliteDatabase&) = delete;
        SqliteDatabase& operator=(const SqliteDatabase&) = delete;
        SqliteDatabase(SqliteDatabase&&) = delete;
        SqliteDatabase& operator=(SqliteDatabase&&) = delete;

        // ----------------------------------------------------------------
        // Schema Initialisation
        // ----------------------------------------------------------------

        /**
         * @brief Create all required tables if they do not yet exist.
         *
         * Idempotent – safe to call on every startup.
         * @throws std::runtime_error on schema error.
         */
        void initSchema();

        // ----------------------------------------------------------------
        // Data Manipulation
        // ----------------------------------------------------------------

        /**
         * @brief Execute a DML/DDL statement that returns no rows.
         *
         * @p params are bound positionally to '?' placeholders in @p sql.
         * @param sql    SQL statement with optional '?' placeholders.
         * @param params Values bound left-to-right to each '?'.
         * @param errmsg If non-null, receives the error message on failure.
         * @return true on success, false on failure.
         */
        bool exec(const std::string& sql, const std::vector<std::string>& params = {}, std::string* errmsg = nullptr);

        /**
         * @brief Execute a SELECT and call @p callback for each result row.
         *
         * @p params are bound positionally to '?' placeholders.
         * @param sql      SELECT statement.
         * @param params   Bound values.
         * @param callback Called once per result row.
         * @param errmsg   Receives the error message on failure.
         * @return true on success (even if zero rows), false on error.
         */
        bool
        query(const std::string& sql, const std::vector<std::string>& params, const RowCallback& callback, std::string* errmsg = nullptr);

        /// Convenience overload without params (SELECT with no placeholders).
        bool query(const std::string& sql, const RowCallback& callback, std::string* errmsg = nullptr);

        // ----------------------------------------------------------------
        // Convenience Accessors
        // ----------------------------------------------------------------

        /// Row-id of the last successful INSERT.
        int64_t lastInsertRowid() const;

        /// Number of rows changed by the last DML statement.
        int changedRows() const;

    private:
        /// Internal helper: prepare a statement and bind parameters.
        /// Returns nullptr on failure and sets *errmsg.
        sqlite3_stmt* prepare(const std::string& sql, const std::vector<std::string>& params, std::string* errmsg);

        sqlite3* db_; ///< Raw SQLite connection handle.
    };

} // namespace snodec::database::sqlite
