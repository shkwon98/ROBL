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

#include "robl_log.hpp"

using namespace std::chrono_literals;

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
#define ROBL_PKT_HDR__SZ (sizeof(T_ROBL_PKT_HDR))

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
// ROBL_INIT status
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

#define EROBL__TIMEOUT (0)

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
    std::shared_ptr<std::byte[]> payload;

    uint32_t next_idx;
    // uint32_t list;
};

struct T_ROBL_MULTI_PKT_REC
{
    T_ROBL_PKT hdr;

    uint32_t len;
    uint8_t *payload;

    uint32_t next;
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
    T_ROBL_MULTI_PKT_REC multi_pkt_rec[ROBL__MULTI_PKT_REC_NO];
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

/*==========================================================================*/

class ROBL_BASE
{
    enum
    {
        EROBL__OK = 0,
        EROBL__UDS_SOCK_FAIL = -1,
        EROBL__UDS_SOCKOPT_FAIL = -2,
        EROBL__UDS_BIND_FAIL = -3,
    };

public:
    ROBL_BASE(void);
    ~ROBL_BASE(void);

protected:
    void InternalCreateThreadROBL(const std::string &pss_name);

private:
    void ThreadROBL(const std::string &pss_name); // thread for ROBL
    int InternalTryMakeUDS(const std::string &pss_name);
    int InternalCheckPacketIntegrity(T_ROBL_PKT *packet, uint32_t bytes);
    uint32_t InternalAllocatePacketRecord(void);
    void InternalPutMidPacket(uint32_t pkt_rec_ix);
    void InternalUnmarshalSinglePacket(T_ROBL_PKT *packet, uint32_t bytes);
    void InternalUnmarshalUdsPacket(T_ROBL_PKT *packet, uint32_t bytes);

    std::thread m_thread_robl;
    std::thread::id m_thread_robl_id;
    uint64_t m_thread_robl_loop_cnt;
    int64_t m_thread_robl_last_tick;

    int m_uds_fd;
    std::filesystem::path m_uds_file_path;

    T_PKT_STAT m_stat_uds;

    T_ROBL_PKT_ASSEMBLY m_packet; // UDS packet receive buffer (by thread ROBL)
};

#include "robl_base_impl.hpp"