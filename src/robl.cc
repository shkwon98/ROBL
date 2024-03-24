#include "robl.h"

namespace ROBL
{

int ROBL::Init(int ac, char **av, const std::string &pss_name)
{
    auto init_progress = 0U;
    int result = EROBL__OK;

    if (result == EROBL__OK)
    {
        init_progress |= ROBL_INIT_PROGRESS__CREATE_THR_ROBL;
        CreateThreadROBL(pss_name);
    }

    if (result == EROBL__OK)
    {
        m_status &= ~ROBL_INIT_PROGRESS__MASK;
        m_status |= (init_progress & ROBL_INIT_PROGRESS__MASK);

        std::cout << "[INIT] done. (init_progress=" << std::hex << init_progress << ")" << std::endl;
    }

    // n.
    return result;
}

std::shared_ptr<MidListener> ROBL::CreateMessageListener(void)
{
    return std::make_shared<MidListener>(GetPacketAssembler());
}

} // namespace ROBL