#pragma once

#include <chrono>
#include <cstdint>
#include <iostream>
#include <thread>

#include "robl_base.h"
#include "robl_mid_listener.h"

using namespace std::chrono_literals;

namespace ROBL
{

class ROBL : private Internal::ROBL_BASE
{
public:
    int Init(int ac, char **av, const std::string &pss_name);

    std::shared_ptr<MidListener> CreateMessageListener(void);

    template <typename T>
    int SendMessage(uint32_t mid, T &msg, uint32_t exp_tick)
    {
        auto ret = 0;

        // 1. make packet header
        auto packet = std::vector<std::byte>(ROBL_PKT_HDR__SZ + ROBL_UDS_PLD_LEN +
                                             BLK_ALIGN(ROBL_PKT_HDR__SZ + ROBL_UDS_PLD_LEN, 128));
        auto &header = reinterpret_cast<T_ROBL_PKT &>(*packet.data());

        if (ret = InitializeUdsPacketHeader(header, sizeof(msg), mid); ret < 0)
        {
            std::cerr << "[MID] InitializeUdsPacketHeader(l:" << sizeof(msg) << ",x:" << mid << ") failed. ret=" << ret
                      << std::endl;
            return ret;
        }

        // 2. make target_uds_file
        // TODO: 멀티캐스트 맵에서 해당 xid에 해당하는 uds 파일을 찾아 헤더에 설정하는 로직 구현 필요
        // target_uds_file = "/tmp/robl_uds_0";

        // 3. sendto target_uds_file
        auto remaining_length = sizeof(msg);
        auto data_pointer = reinterpret_cast<std::byte *>(&msg);
        for (int ix = 0; ix < header.tpn; ix++)
        {
            header.psn = ix;
            header.crc32 = 0U;
            header.pl = (remaining_length > ROBL_UDS_PLD_LEN) ? ROBL_UDS_PLD_LEN : remaining_length;
            header.tick = exp_tick;
            std::memcpy(packet.data() + sizeof(T_ROBL_PKT), data_pointer, header.pl);
            // crc32 는 모든 데이터 설정 후 마지막에 계산
            // header.crc32 = CalculateCrc32(p, ROBL_PKT_HDR__SZ + header.pl, 0U); TODO: CRC32 계산 로직 구현 필요

            // if (ret = SendUdsPacket(packet.data(), sizeof(T_ROBL_PKT) + header.pl, target_uds_file);
            //     ret < 0) // TODO: SendUdsPacket 함수 구현 필요
            // {
            //     std::cerr << "[MID] SendUdsPacket(l:" << ROBL_PKT_HDR__SZ + header.pl << ") failed. ret=" << ret <<
            //     std::endl; return EROBL__UDS_SEND_FAIL;
            // }
            // else
            // {
            //     // TODO: DUMP here
            // }

            remaining_length -= header.pl;
            data_pointer += header.pl;
        }

        return EROBL__OK;
    }

private:
    uint32_t m_status;
    std::string m_pss_name;
};

} // namespace ROBL
