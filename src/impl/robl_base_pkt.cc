#include "robl_base.h"

namespace ROBL
{

int Internal::ROBL_BASE::CheckPacketIntegrity(T_ROBL_PKT *packet, uint32_t bytes)
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

uint32_t Internal::ROBL_BASE::AllocatePacketRecord(void)
{
#if 0
    if (packet_assembler_->pkt_rec__free_head == PKT_REC__NULL)
    {
        retrieve_pkt_rec(); // TODO:: implement retrieve_pkt_rec
    }
#endif

    auto lock = std::unique_lock<std::mutex>(packet_assembler_->mutex.pkt_mutex);
    auto curr_idx = packet_assembler_->pkt_rec__free_head;
    auto &curr_rec = packet_assembler_->pkt_rec[curr_idx];

    packet_assembler_->pkt_rec__free_head = curr_rec.next_idx;
    lock.unlock();

    // clear current record
    std::memset(&curr_rec, 0, sizeof(curr_rec));
    curr_rec.next_idx = PKT_REC__NULL;

    return curr_idx;
}

void Internal::ROBL_BASE::PutMidPacket(uint32_t curr_idx)
{
    auto &curr_rec = packet_assembler_->pkt_rec[curr_idx];

    std::lock_guard<std::mutex> lock(packet_assembler_->mutex.mid_mutex);

    // add to mid list
    if (packet_assembler_->mid.head == PKT_REC__NULL)
    {
        packet_assembler_->mid.head = packet_assembler_->mid.tail = curr_idx;
    }
    else
    {
        packet_assembler_->pkt_rec[packet_assembler_->mid.tail].next_idx = curr_idx;
        packet_assembler_->mid.tail = curr_idx;
    }

    packet_assembler_->mid.put_no++;
    packet_assembler_->mid.last_recv_tick =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

void Internal::ROBL_BASE::UnmarshalSinglePacket(T_ROBL_PKT *packet, uint32_t bytes)
{
    // 1. packet 저장을 위한 PKT_REC index 마련
    auto curr_idx = AllocatePacketRecord();

    // 2. init PKT_REC
    auto &curr_rec = packet_assembler_->pkt_rec[curr_idx];
    curr_rec.xid = packet->xid;
    curr_rec.len = bytes;
    curr_rec.payload = std::make_shared<std::vector<std::byte>>(bytes + BLK_ALIGN(bytes, 128));
    std::memcpy(curr_rec.payload->data(), packet, bytes);
    curr_rec.next_idx = PKT_REC__NULL;

    // 3. xID 별 저장 처리
    PutMidPacket(curr_idx);

    // n. DUMP
    // TODO:: DUMP here
}

uint32_t Internal::ROBL_BASE::AllocateMultiPacketRecord(uint32_t xid)
{

    std::lock_guard<std::mutex> lock(packet_assembler_->mutex.pkt_mutex);

    // 1. 동일한 xid를 가진 MPKT_REC가 남아 있으면 전부 초기화
    for (auto i = 0U; i < packet_assembler_->multi_pkt_rec.size(); i++)
    {
        if (packet_assembler_->multi_pkt_rec[i].hdr.xid == xid)
        {
            packet_assembler_->multi_pkt_rec[i].payload.reset();
            memset((char *)&(packet_assembler_->multi_pkt_rec[i]), 0x00, sizeof(T_ROBL_PKT_REC));
        }
    }

    // 2. 비어있는 MPKT_REC 찾아 인덱스 반환
    packet_assembler_->multi_pkt_rec_using_counter++;
    for (auto i = 0U; i < packet_assembler_->multi_pkt_rec.size(); i++)
    {
        auto idx = (packet_assembler_->multi_pkt_rec_using_counter + i) % packet_assembler_->multi_pkt_rec.size();

        if (packet_assembler_->multi_pkt_rec[idx].hdr.xid == 0)
        {
            return idx;
        }
    }

    // error. no free MPKT_REC
    return PKT_REC__NULL;
}

uint32_t Internal::ROBL_BASE::SearchMultiPacketRecord(uint32_t xid)
{
    for (auto i = 0U; i < packet_assembler_->multi_pkt_rec.size(); i++)
    {
        if (packet_assembler_->multi_pkt_rec[i].hdr.xid == xid)
        {
            return i;
        }
    }

    return PKT_REC__NULL;
}

int Internal::ROBL_BASE::UnmarshalFragmentPacket(T_ROBL_PKT *packet, uint32_t bytes)
{
    // 0. check error
    if (packet == nullptr)
    {
        return EROBL__ARGS_1_ERR;
    }

    if (bytes == 0)
    {
        return EROBL__ARGS_2_ERR;
    }

    if (packet->tpn == 1)
    {
        UnmarshalSinglePacket(packet, bytes);
        return EROBL__OK;
    }

    auto now =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    std::cout << "[PKT-MRX:" << std::dec << now << "] XID=" << std::hex << packet->xid << ",[TPN=" << packet->tpn
              << ", PSN=" << packet->psn << "],[TPL=" << packet->tpl << ", PL=" << packet->pl << "]" << std::endl;

    if (packet->psn == 0) // 1. 첫번째 분할 패킷
    {
        // 1.1. multi packet 저장을 위한 MPKT_REC index 마련
        auto idx = AllocateMultiPacketRecord(packet->xid);
        if (idx == PKT_REC__NULL)
        {
            std::cerr << "[PKT-MRX] AllocateMultiPacketRecord(" << std::hex << packet->xid << ") failed. " << std::endl;
            return EROBL__MPA_ALLOC_MPR_FAIL;
        }

        // 1.2. init MPKT_REC
        auto &curr_multi_packet_rec = packet_assembler_->multi_pkt_rec[idx];
        curr_multi_packet_rec.hdr = *packet;
        curr_multi_packet_rec.hdr.tick = now;
        curr_multi_packet_rec.len = (ROBL_PKT_HDR__SZ + packet->tpl) + BLK_ALIGN((ROBL_PKT_HDR__SZ + packet->tpl), BLK_1K);
        curr_multi_packet_rec.payload = std::make_shared<std::vector<std::byte>>(curr_multi_packet_rec.len);
        std::memcpy(curr_multi_packet_rec.payload->data(), packet, bytes);
    }
    else if ((packet->psn > 0) && (packet->psn < (packet->tpn - 1))) // 2. 중간 분할 패킷
    {
        // 2.1. multi packet 저장을 위한 MPKT_REC index 검색
        auto idx = SearchMultiPacketRecord(packet->xid);
        if (idx == PKT_REC__NULL)
        {
            std::cerr << "[PKT-MRX] <x:" << std::hex << packet->xid << ",t=" << packet->tpn << ",s=" << packet->psn
                      << "> No MULTI_PKT_REC" << std::endl;
            return EROBL__MPA_NO_MPR;
        }

        // 2.2. check MULTI PACKET header
        auto curr_multi_packet_rec = packet_assembler_->multi_pkt_rec[idx];

        // 분할 패킷의 헤더 정보가 변경되었을 경우 확인하기 위함(디버깅용)
        if (curr_multi_packet_rec.hdr.tpl != packet->tpl)
        {
            std::cerr << "[PKT-MRX]tpl changed(" << std::dec << curr_multi_packet_rec.hdr.tpl << "-->" << packet->tpl << ")"
                      << std::endl;
        }
        if (curr_multi_packet_rec.hdr.tpn != packet->tpn)
        {
            std::cerr << "[PKT-MRX]tpn changed(" << std::dec << curr_multi_packet_rec.hdr.tpn << "-->" << packet->tpn << ")"
                      << std::endl;
        }
        if ((curr_multi_packet_rec.hdr.psn + 1) != packet->psn)
        {
            std::cerr << "[PKT-MRX] psn, out of order(" << std::dec << curr_multi_packet_rec.hdr.psn << "-->" << packet->psn
                      << ")" << std::endl;
        }
        if (packet->pl != ROBL_UDS_PLD_LEN)
        {
            std::cerr << "[PKT-MRX] invalid pl(" << std::dec << packet->pl << ":" << ROBL_UDS_PLD_LEN << ")" << std::endl;
        }

        // 2.3. MPKT_REC에 payload 이어붙이기
        if (curr_multi_packet_rec.payload == nullptr) // overflow 등의 이유로 이전 과정에서 payload가 해제된 경우
        {
            std::cerr << "[PKT-MRX] REC.payload is null" << std::endl;
            return EROBL__MPA_BUFFER_NULL;
        }

        auto pos = ROBL_PKT_HDR__SZ + (packet->psn * ROBL_PKT_PLD_LEN);
        if (curr_multi_packet_rec.len < (pos + ROBL_PKT_PLD_LEN)) // overflow check
        {
            std::cerr << "[PKT-MRX] overflow (" << std::dec << curr_multi_packet_rec.len << ", " << pos + ROBL_PKT_PLD_LEN
                      << ") drop..." << std::endl;
            std::memset(&curr_multi_packet_rec.hdr, 0x00, sizeof(curr_multi_packet_rec.hdr));
            curr_multi_packet_rec.len = 0;
            curr_multi_packet_rec.payload.reset();
            return EROBL__MPA_PLD_OVERFLOW;
        }

        std::memcpy(curr_multi_packet_rec.payload->data() + pos, packet + ROBL_PKT_HDR__SZ, ROBL_PKT_PLD_LEN);
        curr_multi_packet_rec.hdr.psn++;
    }
    else if (packet->psn == (packet->tpn - 1)) // 3. 마지막 분할 패킷
    {
        // 3.1. multi packet 저장을 위한 MPKT_REC index 검색
        auto idx = SearchMultiPacketRecord(packet->xid);
        if (idx == PKT_REC__NULL)
        {
            std::cerr << "[PKT-MRX] <x:" << std::hex << packet->xid << ",t=" << packet->tpn << ",s=" << packet->psn
                      << "> No MULTI_PKT_REC" << std::endl;
            return EROBL__MPA_NO_MPR;
        }

        // 3.2. check MULTI PACKET header
        auto curr_multi_packet_rec = packet_assembler_->multi_pkt_rec[idx];

        // 분할 패킷의 헤더 정보가 변경되었을 경우 확인하기 위함(디버깅용)
        if (curr_multi_packet_rec.hdr.tpl != packet->tpl)
        {
            std::cerr << "[PKT-MRX]tpl changed(" << std::dec << curr_multi_packet_rec.hdr.tpl << "-->" << packet->tpl << ")"
                      << std::endl;
        }
        if (curr_multi_packet_rec.hdr.tpn != packet->tpn)
        {
            std::cerr << "[PKT-MRX]tpn changed(" << std::dec << curr_multi_packet_rec.hdr.tpn << "-->" << packet->tpn << ")"
                      << std::endl;
        }
        if ((curr_multi_packet_rec.hdr.psn + 1) != packet->psn)
        {
            std::cerr << "[PKT-MRX] psn, out of order(" << std::dec << curr_multi_packet_rec.hdr.psn << "-->" << packet->psn
                      << ")" << std::endl;
        }
        if (packet->pl != ROBL_UDS_PLD_LEN)
        {
            std::cerr << "[PKT-MRX] invalid pl(" << std::dec << packet->pl << ":" << ROBL_UDS_PLD_LEN << ")" << std::endl;
        }

        // 3.3. MPKT_REC에 payload 이어붙이기
        if (curr_multi_packet_rec.payload == nullptr) // overflow 등의 이유로 이전 과정에서 payload가 해제된 경우
        {
            std::cerr << "[PKT-MRX] REC.payload is null" << std::endl;
            return EROBL__MPA_BUFFER_NULL;
        }

        auto pos = ROBL_PKT_HDR__SZ + (packet->psn * ROBL_PKT_PLD_LEN);
        if (curr_multi_packet_rec.len < (pos + packet->pl)) // overflow check
        {
            std::cerr << "[PKT-MRX] overflow (" << std::dec << curr_multi_packet_rec.len << ", " << pos + packet->pl
                      << ") drop..." << std::endl;
            std::memset(&curr_multi_packet_rec.hdr, 0x00, sizeof(curr_multi_packet_rec.hdr));
            curr_multi_packet_rec.len = 0;
            curr_multi_packet_rec.payload.reset();
            return EROBL__MPA_PLD_OVERFLOW;
        }

        std::memcpy(curr_multi_packet_rec.payload->data() + pos, packet + ROBL_PKT_HDR__SZ, packet->pl);
        curr_multi_packet_rec.hdr.psn++;

        // 3.4. check PSN, TPN
        if ((curr_multi_packet_rec.hdr.psn + 1) != (curr_multi_packet_rec.hdr.tpn))
        {
            std::cerr << "[PKT-MRX] total packet is not match(" << std::dec << curr_multi_packet_rec.hdr.psn + 1 << ","
                      << curr_multi_packet_rec.hdr.tpn << ")" << std::endl;
            std::memset(&curr_multi_packet_rec.hdr, 0x00, sizeof(curr_multi_packet_rec.hdr));
            curr_multi_packet_rec.len = 0;
            curr_multi_packet_rec.payload.reset();
            return EROBL__MPA_TPN_PSN_MISMATCH;
        }

        // 3.5. packet 저장을 위한 PKT_REC index 마련
        auto curr_idx = AllocatePacketRecord();

        // 3.6. init PKT_REC
        auto &curr_rec = packet_assembler_->pkt_rec[curr_idx];
        curr_rec.xid = curr_multi_packet_rec.hdr.xid;
        curr_rec.len = curr_multi_packet_rec.hdr.tpl + ROBL_PKT_HDR__SZ;
        curr_rec.payload = curr_multi_packet_rec.payload;
        curr_rec.next_idx = PKT_REC__NULL;

        // xID 별 저장 처리
        PutMidPacket(curr_idx);

        // n. DUMP
        // TODO: DUMP here
        std::memset(&curr_multi_packet_rec.hdr, 0x00, sizeof(curr_multi_packet_rec.hdr));
        curr_multi_packet_rec.len = 0;
        curr_multi_packet_rec.payload.reset();
        return EROBL__OK;
    }
    else // 4. 그 외 오류 상황
    {
        // 만약 이전에 저장된 MPKT_REC이 있으면 삭제까지 처리 후 리턴
        auto idx = SearchMultiPacketRecord(packet->xid);
        if (idx == PKT_REC__NULL)
        {
            std::cerr << "[PKT-MRX] <x:" << std::hex << packet->xid << ",t=" << packet->tpn << ",s=" << packet->psn
                      << "> No MULTI_PKT_REC" << std::endl;
            return EROBL__MPA_NO_MPR;
        }

        std::cerr << "[PKT-MRX] free(payload), delete MPKT_REC" << std::endl;

        auto &curr_multi_packet_rec = packet_assembler_->multi_pkt_rec[idx];
        std::memset(&curr_multi_packet_rec.hdr, 0x00, sizeof(curr_multi_packet_rec.hdr));
        curr_multi_packet_rec.len = 0;
        curr_multi_packet_rec.payload.reset();
        return EROBL__MPA_BUFFER_NULL;
    }

    return (int)PKT_REC__NULL; // 멀티 패킷에서 조립 미완성 의미
}

int Internal::ROBL_BASE::InitializeUdsPacketHeader(T_ROBL_PKT &header, uint32_t msg_len, uint32_t xid)
{
    if (msg_len > (ROBL_PKT_TPN_MAX * ROBL_UDS_PLD_LEN))
    {
        return EROBL__COMM_TOO_LARGE_MSG;
    }

    header.magic = ROBL_PKT_MAGIC;
    header.tpn = (msg_len == 0U)
                     ? 1U
                     : ((msg_len % ROBL_UDS_PLD_LEN) ? ((msg_len / ROBL_UDS_PLD_LEN) + 1U) : (msg_len / ROBL_UDS_PLD_LEN));
    header.psn = 0U;
    header.tpl = msg_len;

    header.xid = xid;
    header.crc32 = 0U;
    header.tick =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    header.pl = 0U;

    return EROBL__OK;
}

} // namespace ROBL