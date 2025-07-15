/*
 * Universal Performance Collection Library (UPCL)
 * Type definitions and structures
 */

#ifndef _UPCL_TYPES_H
#define _UPCL_TYPES_H

#include <stdint.h>
#include <stdbool.h>

/* Forward declarations */
typedef struct upcl_session *upcl_session_t;

/* Collection methods */
#define UPCL_METHOD_EBPF        (1 << 0)
#define UPCL_METHOD_PERF        (1 << 1)
#define UPCL_METHOD_KPROBE      (1 << 2)
#define UPCL_METHOD_UPROBE      (1 << 3)
#define UPCL_METHOD_TRACEPOINT  (1 << 4)
#define UPCL_METHOD_PMU         (1 << 5)
#define UPCL_METHOD_KMOD        (1 << 6)

/* Data types to collect */
#define UPCL_DATA_CPU_CYCLES    (1 << 0)
#define UPCL_DATA_INSTRUCTIONS  (1 << 1)
#define UPCL_DATA_CACHE_REFS    (1 << 2)
#define UPCL_DATA_CACHE_MISSES  (1 << 3)
#define UPCL_DATA_BRANCHES      (1 << 4)
#define UPCL_DATA_BRANCH_MISSES (1 << 5)
#define UPCL_DATA_PAGE_FAULTS   (1 << 6)
#define UPCL_DATA_CONTEXT_SW    (1 << 7)
#define UPCL_DATA_CPU_MIGRATE   (1 << 8)
#define UPCL_DATA_FUNC_TRACE    (1 << 9)
#define UPCL_DATA_STACK_TRACE   (1 << 10)
#define UPCL_DATA_CUSTOM_PMU    (1 << 11)
#define UPCL_DATA_MEMORY_BW     (1 << 12)
#define UPCL_DATA_POWER         (1 << 13)

/* Output formats */
typedef enum {
    UPCL_FORMAT_BINARY = 0,
    UPCL_FORMAT_JSON,
    UPCL_FORMAT_CSV,
    UPCL_FORMAT_PROTOBUF,
    UPCL_FORMAT_PARQUET,
    UPCL_FORMAT_MSGPACK,
    UPCL_FORMAT_CUSTOM
} upcl_format_t;

/* Error codes */
typedef enum {
    UPCL_SUCCESS = 0,
    UPCL_ERROR_INVALID_PARAM = -1,
    UPCL_ERROR_NO_MEMORY = -2,
    UPCL_ERROR_NO_PERMISSION = -3,
    UPCL_ERROR_NOT_SUPPORTED = -4,
    UPCL_ERROR_DEVICE_BUSY = -5,
    UPCL_ERROR_IO = -6,
    UPCL_ERROR_OVERFLOW = -7,
    UPCL_ERROR_NOT_FOUND = -8,
    UPCL_ERROR_TIMEOUT = -9
} upcl_error_t;

/* CPU architecture */
typedef enum {
    UPCL_ARCH_UNKNOWN = 0,
    UPCL_ARCH_X86_64,
    UPCL_ARCH_ARM64,
    UPCL_ARCH_RISCV64,
    UPCL_ARCH_PPC64
} upcl_arch_t;

/* Sample data structure */
typedef struct upcl_sample {
    /* Basic info */
    uint64_t timestamp;        /* Nanoseconds since boot */
    uint32_t cpu;             /* CPU number */
    uint32_t pid;             /* Process ID */
    uint32_t tid;             /* Thread ID */
    uint64_t ip;              /* Instruction pointer */
    uint64_t addr;            /* Memory address (if applicable) */
    uint64_t period;          /* Sample period */
    uint64_t weight;          /* Sample weight/latency */
    
    /* Hardware counters */
    uint64_t cpu_cycles;
    uint64_t instructions;
    uint64_t cache_references;
    uint64_t cache_misses;
    uint64_t branch_instructions;
    uint64_t branch_misses;
    uint64_t bus_cycles;
    uint64_t stalled_cycles_frontend;
    uint64_t stalled_cycles_backend;
    
    /* Software events */
    uint64_t page_faults;
    uint64_t context_switches;
    uint64_t cpu_migrations;
    uint64_t minor_faults;
    uint64_t major_faults;
    
    /* Memory info */
    uint64_t mem_loads;
    uint64_t mem_stores;
    uint64_t local_mem;
    uint64_t remote_mem;
    uint64_t data_src;        /* Memory hierarchy data source */
    
    /* Stack trace */
    uint32_t nr_stack_entries;
    uint64_t *stack;
    
    /* Function trace */
    char func_name[64];
    uint64_t func_entry_time;
    uint64_t func_duration;
    
    /* Custom data */
    void *custom_data;
    uint32_t custom_data_size;
    
    /* Platform specific */
    union {
        struct {
            uint64_t tsx_abort;
            uint64_t tsx_capacity;
            uint32_t lbr_entries;
            void *lbr_stack;
        } intel;
        struct {
            uint64_t ibs_op_data;
            uint64_t ibs_fetch_data;
            uint64_t ibs_dc_phys;
        } amd;
        struct {
            uint64_t spe_context;
            uint32_t spe_type;
            uint32_t spe_latency;
        } arm;
    } arch_data;
} upcl_sample_t;

/* Configuration structure */
typedef struct upcl_config {
    /* Basic configuration */
    uint32_t methods;          /* Bitmask of UPCL_METHOD_* */
    uint32_t data_types;       /* Bitmask of UPCL_DATA_* */
    uint32_t sample_freq;      /* Sampling frequency in Hz */
    uint64_t sample_period;    /* Or sampling period */
    uint64_t cpu_mask;         /* CPUs to monitor (bitmask) */
    int32_t  pid;             /* Process to monitor (-1 for all) */
    uint32_t mmap_pages;       /* Ring buffer size in pages */
    uint32_t buffer_size;      /* Total buffer size */
    bool     inherit;          /* Monitor child processes */
    bool     exclude_kernel;   /* Exclude kernel events */
    bool     exclude_user;     /* Exclude user events */
    bool     exclude_hv;       /* Exclude hypervisor */
    bool     exclude_idle;     /* Exclude idle */
    
    /* Advanced options */
    bool     use_clockid;      /* Use specific clock */
    int32_t  clockid;         /* Clock ID */
    uint32_t watermark;       /* Wakeup watermark */
    uint32_t aux_pages;       /* AUX area size */
    
    /* Platform-specific options */
    union {
        struct {
            uint32_t precise_ip : 2;
            uint32_t pebs : 1;
            uint32_t lbr : 1;
            uint32_t pt : 1;       /* Intel PT */
            uint32_t bts : 1;      /* Branch Trace Store */
        } intel;
        struct {
            uint32_t ibs_fetch : 1;
            uint32_t ibs_op : 1;
            uint32_t ibs_cnt_ctl : 1;
        } amd;
        struct {
            uint32_t spe : 1;
            uint32_t pmu_version;
            uint32_t brbe : 1;     /* Branch Record Buffer Extension */
        } arm;
    } platform;
    
    /* Output configuration */
    upcl_format_t output_format;
    char *output_path;
    uint32_t output_flags;
    bool compress_output;
    
    /* eBPF specific */
    char *bpf_program_path;
    uint32_t bpf_map_size;
    uint32_t bpf_stack_depth;
    
    /* Custom PMU events */
    struct {
        uint32_t type;
        uint64_t config;
        uint64_t config1;
        uint64_t config2;
        char *name;
        uint64_t sample_period;
    } custom_events[32];
    uint32_t nr_custom_events;
    
    /* Filtering */
    struct {
        uint64_t addr_start;
        uint64_t addr_end;
        char *comm_filter;
        uint32_t *cpu_list;
        uint32_t nr_cpus;
    } filter;
} upcl_config_t;

/* Callback for real-time data processing */
typedef int (*upcl_sample_callback_t)(const upcl_sample_t *sample, void *ctx);

/* Statistics structure */
typedef struct upcl_stats {
    uint64_t samples_collected;
    uint64_t samples_lost;
    uint64_t bytes_written;
    uint64_t events_enabled;
    uint64_t events_running;
    uint64_t buffer_overflows;
    double cpu_usage;
    double memory_usage_mb;
} upcl_stats_t;

/* Platform info structure */
typedef struct upcl_platform_info {
    upcl_arch_t arch;
    char vendor[32];
    char model[64];
    uint32_t family;
    uint32_t model_id;
    uint32_t stepping;
    uint32_t nr_cpus;
    uint32_t nr_cores;
    uint32_t nr_threads;
    uint64_t features;
    char feature_string[256];
} upcl_platform_info_t;

#endif /* _UPCL_TYPES_H */