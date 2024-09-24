#pragma once

#include <fstream>
#include <mutex>

namespace lily::log
{
    /**
     * @brief A class to record and log the duration of SSL/TLS handshakes and SSL/TLS read.
     */
    class ClientLog
    {
    private:
        std::ofstream stream;
        std::mutex mtx;

        ClientLog();

        ClientLog(ClientLog const&)            = delete;
        ClientLog(ClientLog&&)                 = delete;
        ClientLog& operator=(ClientLog const&) = delete;
        ClientLog& operator=(ClientLog&&)      = delete;

    public:
        static ClientLog& getInstance();

        // 
        void write(int64_t hsDurationUs, uint64_t recvSize, int64_t recvDurationUs, uint64_t writeSize, int64_t writeDurationUs);
    };
} // namespace lily::log
