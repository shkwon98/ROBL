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

inline int ROBL_BASE::InternalCheckPacketIntegrity(T_ROBL_PKT_HDR *header, uint32_t bytes)
{
    // 1. check magic number
    if (header->magic != ROBL_PKT_MAGIC)
    {
        return EROBL__PHI_MAGIC_MISMATCH;
    }

    // 2. check length
    if (bytes > ROBL_PKT_LEN)
    {
        return EROBL__PHI_OVER_THE_SIZE_A_PKT;
    }

    // 3. check total packet number
    if (header->tpn == 0)
    {
        return EROBL__PHI_INVALID_TPN;
    }

    // 4. check packet sequence number
    if (header->tpn <= header->psn)
    {
        return EROBL__PHI_INVALID_PSN;
    }

    // 5. check CRC32
    if (check_pkt_crc32(buf, bytes) < 0) // TODO:: implement check_pkt_crc32
    {
        return EROBL__PHI_CRC32_MISMATCH;
    }

    // 6. check packet length
    if (bytes != (ROBL_PKT_HDR__SZ + header->pl))
    {
        return EROBL__PHI_INVALID_PL;
    }

    return EROBL__OK;
}

inline void ROBL_BASE::InternalUnmarshalUdsPacket(T_ROBL_PKT_HDR *header, uint32_t bytes)
{
    // 0. check error
    if (InternalCheckPacketIntegrity(header, bytes) < 0)
    {
        m_stat_uds.rx_err++;
        return;
    }

    // stat
    m_stat_uds.rx_pkt++;
    m_stat_uds.rx_bytes += bytes;

    // processing...
    if (header->tpn == 1)
    {
        // single packet
        InternalUnmarshalSinglePacket(header, bytes);
    }
    else
    {
        // multiple packet (fragment packet)
        InternalUnmarshalFragmentPacket(header, bytes);
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

        const auto *header = reinterpret_cast<T_ROBL_PKT_HDR *>(uds_pkt_buf.data());

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
        else if (header->magic != ROBL_PKT_MAGIC)
        {
            std::cerr << "[UDS-RX] MAGIC(" << std::hex << header->magic << ") mismatch. discard..." << std::endl;
        }
        else
        {
            std::cout << "[UDS-RX] read(uds_fd) succ. xid=" << std::hex << header->xid << ", bytes=" << bytes << std::endl;
            DUMPA(ATL_UDS_sRX, "UDS:PKT:RX", uds_pkt_buf.data(), bytes);
            InternalUnmarshalUdsPacket(uds_pkt_buf.data(), bytes);
        }

        m_thread_robl_last_tick =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
    }
}
