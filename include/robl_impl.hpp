#pragma once

#include "robl.hpp"

inline int ROBL::Init(int ac, char *av[], const std::string &pss_name)
{
    auto init_progress = 0U;
    int result = EROBL__OK;

    if (result == EROBL__OK)
    {
        init_progress |= ROBL_INIT_PROGRESS__CREATE_THR_ROBL;
        InternalCreateThreadROBL(pss_name);
    }

    if (result == EROBL__OK)
    {
        status &= ~ROBL_INIT_PROGRESS__MASK;
        status |= (init_progress & ROBL_INIT_PROGRESS__MASK);

        std::cout << "[INIT] done. (init_progress=" << std::hex << init_progress << ")" << std::endl;
    }

    // n.
    return result;
}
