/*
 * SNode.C SSO/MFA — Rate Limiter (Sliding Window)
 * Copyright (C) Jan Nicolas Eberwein 2025/2026 — Master Thesis
 *
 * In-memory sliding-window rate limiter for login and MFA endpoints.
 * Tracks failed attempts per key (IP address or username) and blocks
 * requests that exceed the configured threshold.
 *
 * Design decisions:
 * - In-memory storage (no database writes per attempt — important for
 *   flash-based OpenWRT storage to minimise write wear).
 * - Sliding window provides smoother rate limiting than fixed windows.
 * - Automatic cleanup of expired entries to prevent memory growth.
 * - Thread-safe via std::mutex.
 *
 * Default: 5 failed attempts per 60-second window.
 */

#pragma once

#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <string>

namespace snodec {
    namespace auth {

        class RateLimiter {
        public:
            /**
             * Construct a rate limiter.
             * @param maxAttempts  Maximum number of failed attempts allowed in the window.
             * @param windowSeconds  Duration of the sliding window in seconds.
             */
            explicit RateLimiter(int maxAttempts = 5, int windowSeconds = 60)
                : maxAttempts_(maxAttempts)
                , windowDuration_(std::chrono::seconds(windowSeconds)) {
            }

            /**
             * Check if a request from the given key is allowed.
             * Returns true if the key has not exceeded the rate limit.
             * Returns false if the key is currently blocked.
             *
             * This method does NOT record a new attempt — call recordFailure()
             * after a failed authentication to increment the counter.
             */
            bool isAllowed(const std::string& key) {
                std::lock_guard<std::mutex> lock(mutex_);
                cleanup(key);
                auto it = attempts_.find(key);
                if (it == attempts_.end()) {
                    return true;
                }
                return static_cast<int>(it->second.size()) < maxAttempts_;
            }

            /**
             * Record a failed authentication attempt for the given key.
             * The attempt timestamp is added to the sliding window.
             */
            void recordFailure(const std::string& key) {
                std::lock_guard<std::mutex> lock(mutex_);
                cleanup(key);
                attempts_[key].push_back(std::chrono::steady_clock::now());
            }

            /**
             * Record a successful authentication for the given key.
             * Clears all recorded failures, effectively resetting the rate limit.
             */
            void recordSuccess(const std::string& key) {
                std::lock_guard<std::mutex> lock(mutex_);
                attempts_.erase(key);
            }

            /**
             * Get the number of remaining attempts for a key before it is blocked.
             */
            int remainingAttempts(const std::string& key) {
                std::lock_guard<std::mutex> lock(mutex_);
                cleanup(key);
                auto it = attempts_.find(key);
                if (it == attempts_.end()) {
                    return maxAttempts_;
                }
                int remaining = maxAttempts_ - static_cast<int>(it->second.size());
                return remaining > 0 ? remaining : 0;
            }

            /**
             * Get the number of seconds until the oldest failure expires
             * (i.e., when the key will be partially unblocked).
             * Returns 0 if the key has no recorded failures.
             */
            int secondsUntilUnblock(const std::string& key) {
                std::lock_guard<std::mutex> lock(mutex_);
                cleanup(key);
                auto it = attempts_.find(key);
                if (it == attempts_.end() || it->second.empty()) {
                    return 0;
                }
                auto oldest = it->second.front();
                auto expiresAt = oldest + windowDuration_;
                auto now = std::chrono::steady_clock::now();
                if (expiresAt <= now) {
                    return 0;
                }
                return static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(expiresAt - now).count());
            }

            /**
             * Periodic cleanup of all expired entries across all keys.
             * Call this periodically (e.g., every 5 minutes) to prevent
             * unbounded memory growth from inactive keys.
             */
            void purgeExpired() {
                std::lock_guard<std::mutex> lock(mutex_);
                auto now = std::chrono::steady_clock::now();
                auto cutoff = now - windowDuration_;

                for (auto it = attempts_.begin(); it != attempts_.end();) {
                    auto& deque = it->second;
                    while (!deque.empty() && deque.front() < cutoff) {
                        deque.pop_front();
                    }
                    if (deque.empty()) {
                        it = attempts_.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

        private:
            int maxAttempts_;
            std::chrono::seconds windowDuration_;
            std::mutex mutex_;

            // Map from key (IP or username) to deque of attempt timestamps
            std::map<std::string, std::deque<std::chrono::steady_clock::time_point>> attempts_;

            // Remove expired entries for a specific key (must hold lock)
            void cleanup(const std::string& key) {
                auto it = attempts_.find(key);
                if (it == attempts_.end())
                    return;

                auto cutoff = std::chrono::steady_clock::now() - windowDuration_;
                auto& deque = it->second;
                while (!deque.empty() && deque.front() < cutoff) {
                    deque.pop_front();
                }
                if (deque.empty()) {
                    attempts_.erase(it);
                }
            }
        };

    } // namespace auth
} // namespace snodec
