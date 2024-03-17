#pragma once

#include "robl_base.hpp"

inline ROBL_BASE::ROBL_BASE(void)
    : m_thread_robl_id(std::thread::id())
    , m_thread_robl_last_tick(0)
    , m_thread_robl_loop_cnt(0)
    , m_uds_fd(0)
    , m_uds_file_path("")
{
}

inline ROBL_BASE::~ROBL_BASE(void)
{
    if (m_uds_fd != 0)
    {
        close(m_uds_fd);
    }
}

inline void ROBL_BASE::InternalCreateThreadROBL(const std::string &pss_name)
{
    m_thread_robl = std::thread(&ROBL_BASE::ThreadROBL, this, pss_name);
    m_thread_robl_id = m_thread_robl.get_id();

    std::cout << "[ROBL:THR-ROBL] THREAD: ThreadROBL start...." << std::endl;
}

inline int ROBL_BASE::InternalTryMakeUDS(const std::string &pss_name)
{
    // 0. 만약 이미 UDS가 열려있다면, 그대로 리턴
    if (m_uds_fd != 0)
    {
        return EROBL__OK;
    }

    // 1. make uds-file-path
    const auto &uds_file_path = std::filesystem::path(ROBL__UDS_PATH) / pss_name;
    std::filesystem::create_directories(ROBL__UDS_PATH);

    // 2. unlink UDS file
    if (std::filesystem::exists(uds_file_path))
    {
        std::filesystem::remove(uds_file_path);
    }

    // 3. get UDS socket
    auto fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        std::cerr << "[ROBL:UDS] UDS socket(AF_UNIX, SOCK_DGRAM) failed. err=" << errno << std::endl;
        return EROBL__UDS_SOCK_FAIL;
    }

    // 4. setup UDS address
    auto uds_addr = sockaddr_un{ .sun_family = AF_UNIX, .sun_path = "" };
    std::strncpy(uds_addr.sun_path, uds_file_path.c_str(), sizeof(uds_addr.sun_path) - 1);

    // 5. bind local address
    if (auto yes = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
    {
        std::cerr << "[ROBL:UDS] setsockopt(SO_REUSEADDR) failed. err=" << errno << std::endl;
        close(fd);
        return EROBL__UDS_SOCKOPT_FAIL;
    }
    if (bind(fd, reinterpret_cast<sockaddr *>(&uds_addr), sizeof(uds_addr)) < 0)
    {
        std::cerr << "[ROBL:UDS] bind() failed. err=" << errno << std::endl;
        close(fd);
        return EROBL__UDS_BIND_FAIL;
    }

    // n. success
    std::cout << "[ROBL:UDS] UDS opened. fd=" << fd << std::endl;
    m_uds_file_path = uds_file_path;
    m_uds_fd = fd;

    return EROBL__OK;
}

inline int ROBL_BASE::InternalCheckPacketIntegrity(T_ROBL_PKT *packet, uint32_t bytes)
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

    // 5. check CRC32
    if (check_pkt_crc32(packet, bytes) < 0) // TODO:: implement check_pkt_crc32
    {
        std::cerr << "[UDS-RX] CRC32 mismatch. discard..." << std::endl;
        return EROBL__PHI_CRC32_MISMATCH;
    }

    // 6. check packet length
    if (bytes != (ROBL_PKT_HDR__SZ + packet->pl))
    {
        std::cerr << "[UDS-RX] packet length(" << bytes << ") mismatch with packet length in packet("
                  << (ROBL_PKT_HDR__SZ + packet->pl) << "). discard..." << std::endl;
        return EROBL__PHI_INVALID_PL;
    }

    return EROBL__OK;
}

inline uint32_t ROBL_BASE::InternalAllocatePacketRecord(void)
{
    if (m_packet.pkt_rec__free_head == PKT_REC__NULL)
    {
        retrieve_pkt_rec(); // TODO:: implement retrieve_pkt_rec
    }

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

inline void ROBL_BASE::InternalPutMidPacket(uint32_t curr_idx)
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
        m_packet.pkt_rec[m_packet.mid.tail].next = curr_idx;
        m_packet.mid.tail = curr_idx;
    }

    m_packet.mid.put_no++;
    m_packet.mid.last_recv_tick =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

inline void ROBL_BASE::InternalUnmarshalSinglePacket(T_ROBL_PKT *packet, uint32_t bytes)
{
    // 1. packet 저장을 위한 PKT_REC index 마련
    auto curr_idx = InternalAllocatePacketRecord();

    // 2. packet payload 저장 공간 alloc
    auto p = std::make_shared<std::byte[]>(bytes + BLK_ALIGN(bytes, 128));

    // payload 저장
    std::memcpy(p.get(), packet, bytes);

    // 3. init PKT_REC
    auto &curr_rec = m_packet.pkt_rec[curr_idx];
    curr_rec.xid = packet->xid;
    curr_rec.len = bytes;
    curr_rec.payload = p;
    curr_rec.next = PKT_REC__NULL;

    // 4. xID 별 저장 처리
    InternalPutMidPacket(curr_idx); // TODO:: implement InternalPutMidPacket

    // n. DUMP
    // TODO:: DUMP here
}

inline void ROBL_BASE::InternalUnmarshalUdsPacket(T_ROBL_PKT *packet, uint32_t bytes)
{
    // 0. check error
    if (InternalCheckPacketIntegrity(packet, bytes) < 0)
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
        InternalUnmarshalSinglePacket(packet, bytes);
    }
    else
    {
        // multiple packet (fragment packet)
        InternalUnmarshalFragmentPacket(packet, bytes);
    }
}

inline void ROBL_BASE::ThreadROBL(const std::string &pss_name) // thread for ROBL
{

    while (true)
    {
        m_thread_robl_loop_cnt++;

        if (InternalTryMakeUDS(pss_name) != EROBL__OK)
        {
            std::this_thread::sleep_for(1s);
            continue;
        }

        auto uds_pkt_buf = std::vector<std::byte>(ROBL_PKT_BUF_LEN, std::byte(0x00));
        auto bytes = read(m_uds_fd, uds_pkt_buf.data(), ROBL_PKT_BUF_LEN); // block until receive message

        const auto *packet = reinterpret_cast<T_ROBL_PKT *>(uds_pkt_buf.data());

        if (bytes < 0)
        {
            std::cerr << "[UDS-RX] read(uds_fd) failed. errno=" << errno << std::endl;
        }
        else if (bytes == 0)
        {
            std::cerr << "[UDS-RX] read(uds_fd)==0" << std::endl;
            shutdown(m_uds_fd, SHUT_RDWR);
            close(m_uds_fd);
            m_uds_fd = 0;
        }
        else if (packet->magic != ROBL_PKT_MAGIC)
        {
            std::cerr << "[UDS-RX] MAGIC(" << std::hex << packet->magic << ") mismatch. discard..." << std::endl;
        }
        else
        {
            std::cout << "[UDS-RX] read(uds_fd) succ. xid=" << std::hex << packet->xid << ", bytes=" << bytes << std::endl;
            DUMPA(ATL_UDS_sRX, "UDS:PKT:RX", uds_pkt_buf.data(), bytes);
            InternalUnmarshalUdsPacket(uds_pkt_buf.data(), bytes);
        }

        m_thread_robl_last_tick =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
    }
}
