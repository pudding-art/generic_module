/*
 * Universal Performance Collection Library (UPCL)
 * Internal definitions and structures
 */

#ifndef _UPCL_INTERNAL_H
#define _UPCL_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <linux/list.h>
#include "upcl.h"

/* Logging macros */
#define UPCL_LOG_LEVEL_ERROR   0
#define UPCL_LOG_LEVEL_WARN    1
#define UPCL_LOG_LEVEL_INFO    2
#define UPCL_LOG_LEVEL_DEBUG   3

extern int g_upcl_log_level;

#define upcl_log(level, fmt, ...) do { \
    if (level <= g_upcl_log_level) { \
        fprintf(stderr, "[UPCL:%s] " fmt, \
                level == UPCL_LOG_LEVEL_ERROR ? "ERROR" : \
                level == UPCL_LOG_LEVEL_WARN ? "WARN" : \
                level == UPCL_LOG_LEVEL_INFO ? "INFO" : "DEBUG", \
                ##__VA_ARGS__); \
    } \
} while (0)

#define upcl_log_error(fmt, ...) upcl_log(UPCL_LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define upcl_log_warn(fmt, ...)  upcl_log(UPCL_LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define upcl_log_info(fmt, ...)  upcl_log(UPCL_LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define upcl_log_debug(fmt, ...) upcl_log(UPCL_LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)

/* List operations (kernel-style) */
#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#endif

#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

#define list_for_each_entry(pos, head, member) \
    for (pos = list_entry((head)->next, typeof(*pos), member); \
         &pos->member != (head); \
         pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member) \
    for (pos = list_entry((head)->next, typeof(*pos), member), \
         n = list_entry(pos->member.next, typeof(*pos), member); \
         &pos->member != (head); \
         pos = n, n = list_entry(n->member.next, typeof(*n), member))

#define INIT_LIST_HEAD(ptr) do { \
    (ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

static inline void list_add(struct list_head *new, struct list_head *head)
{
    head->next->prev = new;
    new->next = head->next;
    new->prev = head;
    head->next = new;
}

static inline void list_del(struct list_head *entry)
{
    entry->next->prev = entry->prev;
    entry->prev->next = entry->next;
    entry->next = entry->prev = entry;
}

/* Ring buffer structure */
struct upcl_ringbuf {
    void *base;
    size_t size;
    size_t mask;
    
    volatile uint64_t head;
    volatile uint64_t tail;
    
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    
    /* Statistics */
    uint64_t nr_samples;
    uint64_t nr_lost;
    uint64_t nr_overflows;
};

/* Exporter structure */
struct upcl_exporter {
    upcl_format_t format;
    void *ctx;
    
    int (*init)(void **ctx, const char *path, bool compress);
    int (*write)(void *ctx, const upcl_sample_t *sample);
    int (*flush)(void *ctx);
    int (*finish)(void *ctx);
    void (*destroy)(void *ctx);
};

/* Forward declarations */
struct upcl_session;

/* Platform detection */
int upcl_platform_detect(upcl_platform_info_t *info);
int upcl_platform_init_intel(void);
int upcl_platform_init_amd(void);
int upcl_platform_init_arm(void);

/* Perf subsystem */
int upcl_perf_init(void);
void upcl_perf_cleanup(void);
void *upcl_perf_create(struct upcl_session *session, const upcl_config_t *config);
void upcl_perf_destroy(void *handle);
int upcl_perf_start(void *handle);
int upcl_perf_stop(void *handle);
int upcl_perf_pause(void *handle);
int upcl_perf_resume(void *handle);
int upcl_perf_get_stats(void *handle, upcl_stats_t *stats);

/* eBPF subsystem */
int upcl_ebpf_init(void);
void upcl_ebpf_cleanup(void);
void *upcl_ebpf_create(struct upcl_session *session, const upcl_config_t *config);
void upcl_ebpf_destroy(void *handle);
int upcl_ebpf_start(void *handle);
int upcl_ebpf_stop(void *handle);
int upcl_ebpf_get_stats(void *handle, upcl_stats_t *stats);

/* Kernel module interface */
void *upcl_kmod_create(struct upcl_session *session, const upcl_config_t *config);
void upcl_kmod_destroy(void *handle);
int upcl_kmod_start(void *handle);
int upcl_kmod_stop(void *handle);

/* Ring buffer operations */
struct upcl_ringbuf *upcl_ringbuf_create(size_t size);
void upcl_ringbuf_destroy(struct upcl_ringbuf *rb);
int upcl_ringbuf_write(struct upcl_ringbuf *rb, const void *data, size_t len);
int upcl_ringbuf_read(struct upcl_ringbuf *rb, void *data, size_t len);
size_t upcl_ringbuf_available(struct upcl_ringbuf *rb);
void upcl_ringbuf_reset(struct upcl_ringbuf *rb);

/* Export functions */
struct upcl_exporter *upcl_exporter_create(upcl_format_t format,
                                          const char *path,
                                          bool compress);
void upcl_exporter_destroy(struct upcl_exporter *exporter);
int upcl_exporter_start(struct upcl_exporter *exporter);
int upcl_exporter_stop(struct upcl_exporter *exporter);
int upcl_exporter_write(struct upcl_exporter *exporter,
                       const upcl_sample_t *sample);
int upcl_exporter_flush(struct upcl_exporter *exporter);

/* Reader thread */
void *upcl_reader_thread(void *arg);

/* Session internal functions */
int upcl_session_process_sample(struct upcl_session *session,
                               const upcl_sample_t *sample);

/* Utility functions */
static inline uint64_t upcl_rdtsc(void)
{
#ifdef __x86_64__
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

static inline int upcl_cpu_id(void)
{
#ifdef __x86_64__
    int cpu;
    __asm__ __volatile__ ("mov %%gs:0x0, %0" : "=r" (cpu));
    return cpu & 0xfff;
#else
    return sched_getcpu();
#endif
}

/* Memory barriers */
#define upcl_mb()    __sync_synchronize()
#define upcl_rmb()   __asm__ __volatile__("lfence" ::: "memory")
#define upcl_wmb()   __asm__ __volatile__("sfence" ::: "memory")

/* Atomic operations */
#define upcl_atomic_inc(ptr) __sync_add_and_fetch(ptr, 1)
#define upcl_atomic_dec(ptr) __sync_sub_and_fetch(ptr, 1)
#define upcl_atomic_add(ptr, val) __sync_add_and_fetch(ptr, val)
#define upcl_atomic_read(ptr) __sync_fetch_and_add(ptr, 0)
#define upcl_atomic_cmpxchg(ptr, old, new) \
    __sync_val_compare_and_swap(ptr, old, new)

/* CPU feature detection */
#ifdef __x86_64__
static inline void upcl_cpuid(uint32_t leaf, uint32_t subleaf,
                             uint32_t *eax, uint32_t *ebx,
                             uint32_t *ecx, uint32_t *edx)
{
    __asm__ __volatile__ ("cpuid"
                         : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
                         : "a" (leaf), "c" (subleaf));
}
#endif

/* MSR access */
#ifdef __x86_64__
static inline uint64_t upcl_rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdmsr" : "=a" (lo), "=d" (hi) : "c" (msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void upcl_wrmsr(uint32_t msr, uint64_t val)
{
    uint32_t lo = val & 0xffffffff;
    uint32_t hi = val >> 32;
    __asm__ __volatile__ ("wrmsr" :: "a" (lo), "d" (hi), "c" (msr));
}
#endif

#endif /* _UPCL_INTERNAL_H */