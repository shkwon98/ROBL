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

    int SendMessage(uint32_t mid, void *msg, uint32_t msg_len, uint16_t dpid, uint32_t exp_tick);

private:
    uint32_t m_status;
    std::string m_pss_name;
};
} // namespace ROBL
