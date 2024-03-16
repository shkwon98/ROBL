#pragma once

#include <chrono>
#include <cstdint>
#include <iostream>
#include <thread>

#include "robl_base.hpp"

using namespace std::chrono_literals;

class ROBL : private ROBL_BASE
{
    enum
    {
        EROBL__OK = 0,
        EROBL__UDS_SOCK_FAIL = -1,
        EROBL__UDS_SOCKOPT_FAIL = -2,
        EROBL__UDS_BIND_FAIL = -3,
    };

public:
    int Init(int ac, char *av[], const std::string &pss_name);

    int SendMessage(uint32_t mid, void *msg, uint32_t msg_len, uint16_t dpid, uint32_t exp_tick);
    int ReceiveMessage(void **ptr, uint32_t timeout);

private:
    uint32_t status;
    std::string m_pss_name;
};

#include "robl_impl.hpp"