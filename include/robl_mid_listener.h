#pragma once

#include <iostream>
#include <thread>
#include <unordered_map>

#include "robl_base.h"
#include "thread_pool.h"

namespace ROBL
{

class MidListener
{
public:
    typedef std::function<void(std::shared_ptr<std::vector<std::byte>> msg_buffer, int msg_len)> MID_CALLBACK_TASK;

    explicit MidListener(std::shared_ptr<T_ROBL_PKT_ASSEMBLY> packet_assembler, int thread_pool_size = 3)
        : packet_assembler_(packet_assembler)
        , task_thread_pool_(ThreadPool{ static_cast<size_t>(thread_pool_size) })
    {
        recv_thread_ = std::thread(&MidListener::Receive, this);
    }

    ~MidListener(void)
    {
        recv_thread_.join();
    }

    template <typename T>
    inline MidListener &InsertCallback(uint32_t mid, void (T::*callback)(std::shared_ptr<std::vector<std::byte>>, int),
                                       T *instance)
    {
        MID_CALLBACK_TASK task = std::bind(callback, instance, std::placeholders::_1, std::placeholders::_2);
        mid_task_hashtable_[mid] = task;

        return *this;
    }

    inline MidListener &InsertCallback(uint32_t mid, MID_CALLBACK_TASK callback)
    {
        mid_task_hashtable_[mid] = callback;

        return *this;
    }

private:
    void Receive(void)
    {
        auto ret = 0;

        while (true)
        {
            auto msg_buffer = std::make_shared<std::vector<std::byte>>();
            ret = ReceiveMessage(msg_buffer, 20); // 20ms timeout

            if (ret < 0)
            {
                std::cerr << "[MID] MidListener:ReceiveMessage() failed. ret = " << ret << std::endl;
            }
            else if (ret > 0)
            {
                auto msg_len = ret;
                if ((msg_buffer == nullptr) || (msg_len < static_cast<int>(ROBL_PKT_HDR__SZ)))
                {
                    continue;
                }

                const auto &header = reinterpret_cast<T_ROBL_PKT *>(msg_buffer->data());
                const auto &mid = header->xid;
                auto it = mid_task_hashtable_.find(mid);
                if (it == mid_task_hashtable_.end())
                {
                    std::cerr << "[MID] Unknown MID(" << std::hex << mid << ") received." << std::endl;
                    continue;
                }

                std::cout << "[MID] MID(" << std::hex << mid << ") received." << std::endl;
                std::cout << "      tpn=" << header->tpn << ", psn=" << header->psn << ", tpl=" << header->tpl << std::endl;
                std::cout << "      len=" << msg_len << std::endl;
                // TODO: DUMP here

                task_thread_pool_.Push(it->second, static_cast<std::shared_ptr<std::vector<std::byte>>>(msg_buffer),
                                       msg_len);
            }
        }
    }

    int ReceiveMessage(std::shared_ptr<std::vector<std::byte>> msg_buffer,
                       uint32_t timeout) // TODO: 추후 PacketAssembler 클래스 구현하여 해당 클래스 메소드로 이동
    {
        // 1. search MID
        int result = EROBL__OK;
        auto mid_rec = PKT_REC__NULL;
        auto mid_len = 0U;

        {
            std::lock_guard<std::mutex> lock(packet_assembler_->mutex.mid_mutex);

            if (packet_assembler_->mid.head != PKT_REC__NULL)
            {
                mid_rec = packet_assembler_->mid.head;
                packet_assembler_->mid.head = packet_assembler_->pkt_rec[mid_rec].next_idx;
                if (packet_assembler_->mid.head == PKT_REC__NULL)
                {
                    packet_assembler_->mid.tail = PKT_REC__NULL;
                }
                packet_assembler_->mid.get_no++;
            }
        }

        // 2. copy MID to user buffer
        if (mid_rec != PKT_REC__NULL)
        {
            mid_len = packet_assembler_->pkt_rec[mid_rec].len;

            // 2.1. copy MID
            auto packet_record = &(packet_assembler_->pkt_rec[mid_rec]);
            if (packet_record->payload == nullptr)
            {
                result = EROBL__MID_BROKEN_RCV_MSG;
            }
            else
            {
                msg_buffer->swap(*packet_record->payload);
                result = mid_len;
            }

            // 2.2. free packet record (mid_rec)
            packet_record->next_idx = PKT_REC__NULL;

            // 2.3. return
            return result;
        }

        // 3. wait to expiration tick // TODO: 추후 std::future, std::promise 사용하여 구현 검토
        auto timeout_tick =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count() +
            timeout;
        while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                   .count() < timeout_tick)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));

            if (packet_assembler_->mid.put_no != packet_assembler_->mid.get_no)
            {
                break;
            }
        }

        if (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count() >= timeout_tick)
        {
            return EROBL__TIMEOUT;
        }

        {
            std::lock_guard<std::mutex> lock(packet_assembler_->mutex.mid_mutex);

            if (packet_assembler_->mid.head != PKT_REC__NULL)
            {
                mid_rec = packet_assembler_->mid.head;
                packet_assembler_->mid.head = packet_assembler_->pkt_rec[mid_rec].next_idx;
                if (packet_assembler_->mid.head == PKT_REC__NULL)
                {
                    packet_assembler_->mid.tail = PKT_REC__NULL;
                }
                packet_assembler_->mid.get_no++;
            }
        }

        // 2. copy MID to user buffer
        if (mid_rec != PKT_REC__NULL)
        {
            mid_len = packet_assembler_->pkt_rec[mid_rec].len;

            // 2.1. copy MID
            auto packet_record = &(packet_assembler_->pkt_rec[mid_rec]);
            if (packet_record->payload == nullptr)
            {
                result = EROBL__MID_BROKEN_RCV_MSG;
            }
            else
            {
                msg_buffer->swap(*packet_record->payload);
                result = mid_len;
            }

            // 2.2. free packet record (mid_rec)
            packet_record->next_idx = PKT_REC__NULL;

            // 2.3. return
            return result;
        }

        // n. (mid_rec == PKT_REC__NULL)
        return EROBL__MID_BROKEN_RCV_MSG;
    }

    std::shared_ptr<T_ROBL_PKT_ASSEMBLY> packet_assembler_;

    std::thread recv_thread_;

    std::unordered_map<uint32_t, MID_CALLBACK_TASK> mid_task_hashtable_;
    ThreadPool task_thread_pool_;
};

} // namespace ROBL
