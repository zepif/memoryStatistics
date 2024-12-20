#ifndef BIN_REPOS_MEMSTATICS_H
#define BIN_REPOS_MEMSTATICS_H

#include <functional>
#include <mutex>
#include <thread>

#include "imap.h"
#include "stddef.h"
#include "stdint.h"

#define TRACE_BACKTRACE

namespace {
    const char* DUMP_LOG_FILE = "/usr/alg_model/mem_dump.log";
    const uint8_t STACK_DEPTH = 30;
    const uint32_t HASH_BUCKET_SIZE = 3000;
} // namespace

struct mem_node {
    uint32_t seq;
    void* addr;
    uint32_t size;
    pid_t tid;
    uint8_t stack_cnt;
    void* stack[STACK_DEPTH];
    time_t time_stamp;
};

class MemStatistics {
public:
    explicit MemStatistics(size_t size);
    ~MemStatistics();

    /************ static area **************/
    static MemStatistics& get();
    static void initMemStatistics(size_t size);
    
    // whether statistics is running
    static bool m_statistics_running;

    // Process command
    [[noreturn]] 
    void procCmd();

    // Memory node management
    void addMemNode(void* addr, size_t size);
    int removeMemNode(void* addr);
    void clearAllMemNodes();
    void dumpMemNodes();
    void procMemNode(void* data);

    // Flags
    bool m_dump_once;
    bool m_debug_flag;
    bool m_append_modle;
    // malloc trim
    bool m_malloc_trim_once;
    bool m_thread_running_flag;

    // Static members
    static int m_log_fd;
    static int m_malloc_status_fd;
    static void *m_malloc_info_fd;


    static thread_local bool sm_statistics_locking;
    static thread_local pid_t thread_id;

private:
    std::thread m_thread;
    bool m_init_flag;
    uint32_t m_seq;
    uint64_t m_allocatedMemSize;
    uint64_t m_activeMemSize;
    uint64_t m_activeMemCnt;
    uint64_t m_appendMemSize;
    uint64_t m_appendMemCnt;
    uint64_t m_peakActiveMemSize;
    IMap m_addr_map;

    // Static instance
    static MemStatistics* m_memStatistics;
};

#define MemIst MemStatistics::get()

#endif // BIN_REPOS_MEMSTATICS_H

