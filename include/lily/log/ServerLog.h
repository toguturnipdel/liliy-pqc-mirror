#pragma once

#include <fstream>
#include <mutex>

namespace lily::log
{
    /**
     * @brief A class to record and log the duration of SSL/TLS handshakes and SSL/TLS read.
     */
    class ServerLog
    {
    private:
        std::ofstream stream;
        std::mutex mtx;

        ServerLog();

        ServerLog(ServerLog const&)            = delete;
        ServerLog(ServerLog&&)                 = delete;
        ServerLog& operator=(ServerLog const&) = delete;
        ServerLog& operator=(ServerLog&&)      = delete;

    public:
        static ServerLog& getInstance();

        // 
        void write(int64_t hsDurationUs, uint64_t recvSize, int64_t recvDurationUs, uint64_t writeSize, int64_t writeDurationUs);
    };
} // namespace lily::log
