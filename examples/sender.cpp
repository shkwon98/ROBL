#include <robl.h>

#pragma pack(1)
struct T_SAMPLE_MSG
{
    uint32_t age;
    uint32_t height;
};
#pragma pop()

int main(int ac, char **av)
{
    ROBL::ROBL robl;
    robl.Init(ac, av, "sender");

    auto sample_msg = T_SAMPLE_MSG{ 20, 180 };
    robl.SendMessage<T_SAMPLE_MSG>(0x4dcd0001, sample_msg, 1000);

    return 0;
}