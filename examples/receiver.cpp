#include <robl.h>

#pragma pack(1)
struct T_SAMPLE_MSG
{
    uint32_t age;
    uint32_t height;
};
#pragma pack()

int main(int ac, char **av)
{
    ROBL::ROBL robl;
    robl.Init(ac, av, "receiver");

    T_SAMPLE_MSG sample_msg = { 30, 180 };
    auto Callback = [](std::shared_ptr<std::vector<std::byte>> msg_buffer, int msg_len) {
        auto *msg = reinterpret_cast<T_SAMPLE_MSG *>(msg_buffer->data());
        std::cout << "age: " << msg->age << ", height: " << msg->height << std::endl;
    };

    auto listener = robl.CreateMessageListener();
    listener->InsertCallback(0x4dcd0001, Callback);

    return 0;
}