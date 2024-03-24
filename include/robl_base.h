#pragma once

#include <array>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <vector>

// #include "robl_log.hpp"

using namespace std::chrono_literals;

namespace ROBL
{

/*==========================================================================*/

#pragma pack(push, 1)

typedef struct
{
    uint32_t magic; // 'ROBL', 0x524F424CU
    uint16_t stid;  // source ROBL thread ID
    uint16_t dtid;  // dest ROBL thread ID
    uint16_t tpn;   // Total Packet Number
    uint16_t psn;   // Packet Sequence Number
    uint32_t tpl;   // Total Packet Length

    uint32_t xid;   // IDentifier
    uint32_t crc32; // CRC32 of <ROBL-HDR + ROBL-PAYLOAD> (calc on crc32=0)
    uint32_t tick;  // monotonic tick
    uint32_t pl;    // packet length

    uint8_t payload[0];
} T_ROBL_PKT;
#define ROBL_PKT_HDR__SZ (sizeof(T_ROBL_PKT))

#pragma pack(pop)

/*-------------------------------------------------------------------------*/

// ROBL constructor, destructor, option
#define ROBL__PSS_LOCK_FILE_PATH "/tmp/robl/lock"
#define ROBL__PSS_LOCK_FILE_PFX  "pss" // prefix
#define ROBL__PSS_LOCK_FILE_PERM (0600)

#define ROBL__SYS_PROC_PATH "/proc"

#define ROBL__UDS_PATH    "/tmp/robl/uds"
#define ROBL__UDS_PSS_PFX "pss"

#define ROBL__SOCK_FD_BEGIN (3)

/*-------------------------------------------------------------------------*/

// block size

#define KB ((uint32_t)1024U)
#define MB ((uint32_t)(KB * KB))

#define BLK_1K ((uint32_t)(1 * KB))

#define BLK_KB(n)       ((uint32_t)(n * KB))
#define BLK_MB(n)       ((uint32_t)(n * MB))
#define BLK_ALIGN(a, b) ((uint32_t)((b) - ((a) % (b))))

/*-------------------------------------------------------------------------*/

#define ROBL_PKT_PLD_LEN (1408U)
#define ROBL_UDS_PLD_LEN (ROBL_PKT_PLD_LEN) // 16B * 88
#define ROBL_UDP_PLD_LEN (ROBL_PKT_PLD_LEN) // 16B * 88

#define ROBL_PKT_LEN     (ROBL_PKT_PLD_LEN + ROBL_PKT_HDR__SZ)
#define ROBL_UDS_PKT_LEN (ROBL_UDS_PLD_LEN + ROBL_PKT_HDR__SZ)
#define ROBL_UDP_PKT_LEN (ROBL_UDP_PLD_LEN + ROBL_PKT_HDR__SZ)

/*-------------------------------------------------------------------------*/

#define ROBL_PKT_MAGIC (0x524F424CU) // 'ROBL'

#define ROBL_PKT_TPN_MIN (1)
#define ROBL_PKT_TPN_MAX (65535)

#define ROBL_PKT_PSN_MIN (ROBL_PKT_TPN_MIN - 1)
#define ROBL_PKT_PSN_MAX (ROBL_PKT_TPN_MAX - 1)

#define ROBL_PKT_BUF_LEN (ROBL_PKT_LEN + BLK_ALIGN(ROBL_PKT_LEN, BLK_1K))

/*-------------------------------------------------------------------------*/
// ROBL_INIT m_status
#define ROBL_INIT_PROGRESS__MAKE_LOCK_FILE  (0x01U)
#define ROBL_INIT_PROGRESS__ATTACH_SHM      (0x02U)
#define ROBL_INIT_PROGRESS__CHECK_CRC       (0x04U)
#define ROBL_INIT_PROGRESS__MAKE_UDS        (0x08U)
#define ROBL_INIT_PROGRESS__CREATE_THR_ROBL (0x10U)
#define ROBL_INIT_PROGRESS__MASK            (0x1fU)

#define ROBL_STS__THR_ROBL__RUNNING (0x0100U)
#define ROBL_STS__THR_CLI__RUNNING  (0x0200U)

#define ROBL_EXIT_CODE__INIT (0xFFFFFFFFU)
#define ROBL_EXIT_CODE__NORM (0xFFFFEEEEU)

#define ROBL_UDS_MODE__ROBL   (0)
#define ROBL_UDS_MODE__DAEMON (1)

#define ROBL_LOG_CH__SHM (0)
#define ROBL_LOG_CH__CON (1)

/*-------------------------------------------------------------------------*/

#define EROBL__OK      (0)
#define EROBL__TIMEOUT (0)

// 31. UDS
#define EROBL__UDS_FAIL           (-310)
#define EROBL__UDS_SOCK_FAIL      (-311)
#define EROBL__UDS_SOCK_OPEN_FAIL (-312)
#define EROBL__UDS_SOCKOPT_FAIL   (-313)
#define EROBL__UDS_BIND_FAIL      (-314)
#define EROBL__UDS_SEND_FAIL      (-315)
#define EROBL__UDS_RECV_FAIL      (-316)
#define EROBL__UDS_INVALID_PSS_ID (-319)

// 0. ROBL arguments error
#define EROBL__ARGS_1_ERR (-1)
#define EROBL__ARGS_2_ERR (-2)
#define EROBL__ARGS_3_ERR (-3)
#define EROBL__ARGS_4_ERR (-4)
#define EROBL__ARGS_5_ERR (-5)
#define EROBL__ARGS_6_ERR (-6)
#define EROBL__ARGS_7_ERR (-7)
#define EROBL__ARGS_8_ERR (-8)
#define EROBL__ARGS_9_ERR (-9)

// 1. ROBL arguments processing error
#define EROBL__INVALID_ARGS     (-10)
#define EROBL__ARGS_1_PROC_FAIL (-11)
#define EROBL__ARGS_2_PROC_FAIL (-12)
#define EROBL__ARGS_3_PROC_FAIL (-13)
#define EROBL__ARGS_4_PROC_FAIL (-14)
#define EROBL__ARGS_5_PROC_FAIL (-15)
#define EROBL__ARGS_6_PROC_FAIL (-16)
#define EROBL__ARGS_7_PROC_FAIL (-17)
#define EROBL__ARGS_8_PROC_FAIL (-18)
#define EROBL__ARGS_9_PROC_FAIL (-19)

// 11. ROBL_INIT
#define EROBL__ROBL_NO_INIT      (-110)
#define EROBL__ROBL_INIT_ALREADY (-111)
#define EROBL__INVALID_PSS_ID    (-112)
#define EROBL__THR_ROBL_FAILED   (-113)
#define EROBL__THR_CLI_FAILED    (-114)

#define EROBL__UNDEF_PSS_ID     (-121)
#define EROBL__MAKE_LOCK_FAIL   (-122)
#define EROBL__PSS_LOCK_ERR     (-123)
#define EROBL__APP_RUNNING      (-124)
#define EROBL__SHMGET_FAIL__CFG (-125)
#define EROBL__SHMAT_FAIL__CFG  (-126)
#define EROBL__CLA_ERROR        (-127)

// 30. COMM (Communications: common)
#define EROBL__COMM_NO_SERVICE            (-300)
#define EROBL__COMM_FRAG_PKT_HANDLER_FAIL (-301)
#define EROBL__COMM_BROKEN_RCV_MSG        (-302)
#define EROBL__COMM_PKT_INTEGRITY_FAIL    (-303)
#define EROBL__COMM_PKT_HDR_FAIL          (-304)
#define EROBL__COMM_DEST_HOST_UNKNOWN     (-305)
#define EROBL__COMM_MSG_BUFLEN_ERR        (-306)
#define EROBL__COMM_NO_MESSAGE            (-307)
#define EROBL__COMM_TOO_LARGE_MSG         (-308)

// 40. MID
#define EROBL__NO_SUCH_MID          (-400)
#define EROBL__MID_UDS_NOT_OPEN     (-401)
#define EROBL__MID_BROKEN_RCV_MSG   (-402)
#define EROBL__MID_NO_SUCH_FREE_MEM (-403)

// 35. PACKET HEADER INTEGRITY
#define EROBL__PHI_MAGIC_MISMATCH      (-350)
#define EROBL__PHI_OVER_THE_SIZE_A_PKT (-351)
#define EROBL__PHI_INVALID_DST_POR_ID  (-352)
#define EROBL__PHI_INVALID_DST_PSS_ID  (-353)
#define EROBL__PHI_INVALID_TPN         (-354)
#define EROBL__PHI_INVALID_PSN         (-355)
#define EROBL__PHI_INVALID_PL          (-356)
#define EROBL__PHI_CRC32_MISMATCH      (-357)

// 36. MUTLIPLE PACKET ASSEMBLY
#define EROBL__MPA_SINGLE_PKT_MSG   (-360)
#define EROBL__MPA_ALLOC_MPR_FAIL   (-361) // Multi Packet Record
#define EROBL__MPA_MALLOC_FAIL      (-362) // multi-pkt payload buffer
#define EROBL__MPA_NO_MPR           (-363)
#define EROBL__MPA_BUFFER_NULL      (-364)
#define EROBL__MPA_PLD_OVERFLOW     (-365)
#define EROBL__MPA_TPN_PSN_MISMATCH (-366)
#define EROBL__MPA_INVALID_TPN      (-367)
#define EROBL__MPA_INVALID_XID      (-368)

/*==========================================================================*/

// MID 수신 저장소

#define PKT_REC__NULL          ((uint32_t)0x0000ffffU)
#define ROBL__PKT_REC_NO       (1024)
#define ROBL__MULTI_PKT_REC_NO (32)
#define PKT_MULTI__TIMEOUT     (1 * SEC)

struct T_ROBL_PKT_META
{
    volatile uint32_t put_no;
    volatile uint32_t get_no;
    uint32_t head;
    uint32_t tail;

    int64_t last_recv_tick;
    pthread_t wait_tid;
};

struct T_ROBL_PKT_MUTEX
{
    std::mutex uds_mutex;
    std::mutex pkt_mutex;

    std::mutex mid_mutex;
};

struct T_ROBL_PKT_REC
{
    uint32_t xid;
    uint32_t len;
    std::shared_ptr<std::vector<std::byte>> payload;

    uint32_t next_idx;
    // uint32_t list;
};

struct T_ROBL_MULTI_PKT_REC
{
    T_ROBL_PKT hdr;
    uint32_t len;
    std::shared_ptr<std::vector<std::byte>> payload;
};

struct T_ROBL_PKT_ASSEMBLY
{
    T_ROBL_PKT_META mid;

    T_ROBL_PKT_MUTEX mutex;

    std::array<T_ROBL_PKT_REC, ROBL__PKT_REC_NO> pkt_rec;
    uint32_t pkt_rec__free_head;
    uint32_t pkt_rec__free_tail;
    uint32_t pkt_rec__free_list;

    uint32_t multi_pkt_rec_using_counter;
    std::array<T_ROBL_MULTI_PKT_REC, ROBL__MULTI_PKT_REC_NO> multi_pkt_rec;
};

struct T_PKT_STAT
{
    uint32_t rx_pkt;
    uint32_t tx_pkt;
    uint64_t rx_bytes;
    uint64_t tx_bytes;

    uint32_t rx_err;
    uint32_t tx_err;
    uint32_t crc_err;
};
} // namespace ROBL

/*==========================================================================*/

namespace ROBL::Internal
{
class ROBL_BASE
{
public:
    ROBL_BASE(void);
    ~ROBL_BASE(void);

protected:
    /**
     * @brief Creates a thread for ROBL.
     *
     * This function creates a thread for ROBL with the specified name.
     *
     * @param pss_name The name of the process.
     */
    void CreateThreadROBL(const std::string &pss_name);

    std::shared_ptr<T_ROBL_PKT_ASSEMBLY> GetPacketAssembler(void)
    {
        return packet_assembler_;
    }

    int InitializeUdsPacketHeader(T_ROBL_PKT &header, uint32_t msg_len, uint32_t xid);

private:
    /**
     * @brief Thread for ROBL.
     *
     * This function represents the thread for ROBL. It takes a string parameter `pss_name` as input.
     *
     * @param pss_name The name of the process.
     */
    void ThreadROBL(const std::string &pss_name); // thread for ROBL

    /**
     * Tries to make a UDS (Unix Domain Socket) with the given pss_name.
     *
     * @param pss_name The name of the process to be used in the UDS file path.
     * @return Returns an integer indicating the success or failure of the operation.
     */
    int TryMakeUDS(const std::string &pss_name);

    /**
     * @brief Unmarshals a UDS packet.
     *
     * This function is responsible for unmarshaling a UDS packet into a T_ROBL_PKT structure.
     *
     * @param packet A pointer to the T_ROBL_PKT structure where the original UDS packet is stored.
     * @param bytes The number of bytes in the UDS packet.
     */
    void UnmarshalUdsPacket(T_ROBL_PKT *packet, uint32_t bytes);

    /**
     * @brief Checks the integrity of a ROBL packet.
     *
     * This function verifies the integrity of a ROBL packet by performing various checks on it.
     *
     * @param packet A pointer to the ROBL packet to be checked.
     * @param bytes The number of bytes in the packet.
     * @return An integer value indicating the result of the integrity check.
     *         - 0 if the packet is valid.
     *         - Non-zero if the packet is invalid.
     */
    int CheckPacketIntegrity(T_ROBL_PKT *packet, uint32_t bytes);

    /**
     * @brief Allocates a packet record.
     *
     * This function is responsible for allocating a packet record. It returns a unique identifier
     * for the allocated packet record.
     *
     * @return The unique identifier of the allocated packet record.
     */
    uint32_t AllocatePacketRecord(void);

    /**
     * Puts a mid-packet at the specified current index.
     *
     * @param curr_idx The current index to put the mid-packet at.
     */
    void PutMidPacket(uint32_t pkt_rec_ix);

    /**
     * Unmarshals a single packet of the ROBL_BASE protocol.
     *
     * @param packet The pointer to the packet structure to be filled with the unmarshaled data.
     * @param bytes The number of bytes in the packet.
     */
    void UnmarshalSinglePacket(T_ROBL_PKT *packet, uint32_t bytes);

    /**
     * @brief Allocates a multi-packet record for the given xID.
     *
     * This function is responsible for allocating a multi-packet record for the specified
     * xID. The multi-packet record is used to store information about a transaction
     * that spans multiple packets.
     *
     * @param xid The xID for which to allocate the multi-packet record.
     * @return The allocated multi-packet record ID.
     */
    uint32_t AllocateMultiPacketRecord(uint32_t xid);

    /**
     * @brief Searches for a multi-packet record with the given xID.
     *
     * This function searches for a multi-packet record with the specified xID.
     *
     * @param xid The xID to search for.
     * @return The index of the multi-packet record if found, or 0 if not found.
     */
    uint32_t SearchMultiPacketRecord(uint32_t xid);

    /**
     * Unmarshals a fragment packet of the ROBL protocol.
     *
     * This function is responsible for unmarshaling a fragment packet of the ROBL protocol.
     * It takes a pointer to a T_ROBL_PKT structure and the number of bytes in the packet as input.
     * The function performs the necessary operations to unmarshal the packet and update the T_ROBL_PKT structure.
     *
     * @param packet A pointer to a T_ROBL_PKT structure representing the packet to be unmarshaled.
     * @param bytes The number of bytes in the packet.
     * @return An integer value indicating the success or failure of the unmarshaling operation.
     */
    int UnmarshalFragmentPacket(T_ROBL_PKT *packet, uint32_t bytes);

    // TODO: 멀티캐스트 그룹 생성: 자신이 처리할 메시지ID 목록에 대한 정보 공유 이를 받으면
    // std::unordered_map<메시지 ID, UDS 소켓경로>에 저장

    std::thread m_thread_robl;
    std::thread::id m_thread_robl_id;
    uint64_t m_thread_robl_loop_cnt;
    int64_t m_thread_robl_last_tick;

    int m_uds_fd;
    std::filesystem::path m_uds_file_path;

    T_PKT_STAT m_stat_uds;

    std::shared_ptr<T_ROBL_PKT_ASSEMBLY> packet_assembler_; // UDS packet receive buffer (by thread ROBL)
};

} // namespace ROBL::Internal
