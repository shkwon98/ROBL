#include "robl_base.h"

namespace ROBL
{

inline int Internal::ROBL_BASE::CheckPacketIntegrity(T_ROBL_PKT *packet, uint32_t bytes)
{
    // 1. check magic number
    if (packet->magic != ROBL_PKT_MAGIC)
    {
        std::cerr << "[UDS-RX] MAGIC(" << std::hex << packet->magic << ") mismatch. discard..." << std::endl;
        return EROBL__PHI_MAGIC_MISMATCH;
    }

    // 2. check length
    if (bytes > ROBL_PKT_LEN)
    {
        std::cerr << "[UDS-RX] packet length(" << bytes << ") over the size of a packet(" << ROBL_PKT_LEN << "). discard..."
                  << std::endl;
        return EROBL__PHI_OVER_THE_SIZE_A_PKT;
    }

    // 3. check total packet number
    if (packet->tpn == 0)
    {
        std::cerr << "[UDS-RX] total packet number is 0. discard..." << std::endl;
        return EROBL__PHI_INVALID_TPN;
    }

    // 4. check packet sequence number
    if (packet->tpn <= packet->psn)
    {
        std::cerr << "[UDS-RX] packet sequence number(" << packet->psn << ") is over the total packet number(" << packet->tpn
                  << "). discard..." << std::endl;
        return EROBL__PHI_INVALID_PSN;
    }

#if 0
    // 5. check CRC32
    if (check_pkt_crc32(packet, bytes) < 0) // TODO:: implement check_pkt_crc32
    {
        std::cerr << "[UDS-RX] CRC32 mismatch. discard..." << std::endl;
        return EROBL__PHI_CRC32_MISMATCH;
    }
#endif

    // 6. check packet length
    if (bytes != (ROBL_PKT_HDR__SZ + packet->pl))
    {
        std::cerr << "[UDS-RX] packet length(" << bytes << ") mismatch with packet length in packet("
                  << (ROBL_PKT_HDR__SZ + packet->pl) << "). discard..." << std::endl;
        return EROBL__PHI_INVALID_PL;
    }

    return EROBL__OK;
}

inline uint32_t Internal::ROBL_BASE::AllocatePacketRecord(void)
{
#if 0
    if (m_packet.pkt_rec__free_head == PKT_REC__NULL)
    {
        retrieve_pkt_rec(); // TODO:: implement retrieve_pkt_rec
    }
#endif

    auto lock = std::unique_lock<std::mutex>(m_packet.mutex.pkt_mutex);
    auto curr_idx = m_packet.pkt_rec__free_head;
    auto &curr_rec = m_packet.pkt_rec[curr_idx];

    m_packet.pkt_rec__free_head = curr_rec.next_idx;
    lock.unlock();

    // clear current record
    std::memset(&curr_rec, 0, sizeof(curr_rec));
    curr_rec.next_idx = PKT_REC__NULL;

    return curr_idx;
}

inline void Internal::ROBL_BASE::PutMidPacket(uint32_t curr_idx)
{
    auto &curr_rec = m_packet.pkt_rec[curr_idx];
    auto ix = 0;

    std::lock_guard<std::mutex> lock(m_packet.mutex.mid_mutex);

    // add to mid list
    if (m_packet.mid.head == PKT_REC__NULL)
    {
        m_packet.mid.head = m_packet.mid.tail = curr_idx;
    }
    else
    {
        m_packet.pkt_rec[m_packet.mid.tail].next_idx = curr_idx;
        m_packet.mid.tail = curr_idx;
    }

    m_packet.mid.put_no++;
    m_packet.mid.last_recv_tick =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

inline void Internal::ROBL_BASE::UnmarshalSinglePacket(T_ROBL_PKT *packet, uint32_t bytes)
{
    // 1. packet 저장을 위한 PKT_REC index 마련
    auto curr_idx = AllocatePacketRecord();

    // 2. packet payload 저장 공간 alloc
    auto p = std::make_shared<std::vector<std::byte>>(bytes + BLK_ALIGN(bytes, 128));

    // payload 저장
    std::memcpy(p->data(), packet, bytes);

    // 3. init PKT_REC
    auto &curr_rec = m_packet.pkt_rec[curr_idx];
    curr_rec.xid = packet->xid;
    curr_rec.len = bytes;
    curr_rec.payload = p;
    curr_rec.next_idx = PKT_REC__NULL;

    // 4. xID 별 저장 처리
    PutMidPacket(curr_idx); // TODO:: implement PutMidPacket

    // n. DUMP
    // TODO:: DUMP here
}

inline void Internal::ROBL_BASE::UnmarshalUdsPacket(T_ROBL_PKT *packet, uint32_t bytes)
{
    // 0. check error
    if (CheckPacketIntegrity(packet, bytes) < 0)
    {
        m_stat_uds.rx_err++;
        return;
    }

    // stat
    m_stat_uds.rx_pkt++;
    m_stat_uds.rx_bytes += bytes;

    // processing...
    if (packet->tpn == 1)
    {
        // single packet
        UnmarshalSinglePacket(packet, bytes);
    }
    else
    {
        // multiple packet (fragment packet)
        // InternalUnmarshalFragmentPacket(packet, bytes); // TODO:: implement InternalUnmarshalFragmentPacket
    }
}

} // namespace ROBL