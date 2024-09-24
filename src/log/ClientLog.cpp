#include <fmt/chrono.h>
#include <spdlog/spdlog.h>

#include <lily/log/ClientLog.h>

namespace lily::log
{
    static auto BOOTSTRAP_TIME {std::time(nullptr)};

    ClientLog::ClientLog()
    {
        //
        this->stream.open(fmt::format("{:%F_%T}_log_client.csv", fmt::localtime(BOOTSTRAP_TIME)));
        if (!this->stream.is_open())
        {
            spdlog::error("Failed to create client record log");
            std::exit(EXIT_FAILURE);
        }
        static constexpr std::string_view HEADER {
            "hs_duration_us;write_size;write_duration_us;recv_size;recv_duration_us\r\n"};
        this->stream.write(HEADER.data(), HEADER.size());
        this->stream.flush();
    }

    ClientLog& ClientLog::getInstance()
    {
        static ClientLog instance {};
        return instance;
    }

    void ClientLog::write(int64_t hsDurationUs, uint64_t writeSize, int64_t writeDurationUs, uint64_t recvSize,
                          int64_t recvDurationUs)
    {
        auto log {
            fmt::format("{};{};{};{};{}\r\n", hsDurationUs, writeSize, writeDurationUs, recvSize, recvDurationUs)};
        std::lock_guard lock {this->mtx};
        this->stream.write(log.c_str(), log.size());
        this->stream.flush();
    }
} // namespace lily::log
