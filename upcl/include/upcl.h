/*
 * Universal Performance Collection Library (UPCL)
 * Main API header file
 */

#ifndef _UPCL_H
#define _UPCL_H

#include "upcl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Library version */
#define UPCL_VERSION_MAJOR 1
#define UPCL_VERSION_MINOR 0
#define UPCL_VERSION_PATCH 0
#define UPCL_VERSION_STRING "1.0.0"

/* ========== Core API Functions ========== */

/**
 * Initialize the UPCL library
 * @return 0 on success, negative error code on failure
 */
int upcl_init(void);

/**
 * Cleanup library resources
 */
void upcl_cleanup(void);

/**
 * Get library version string
 * @return Version string
 */
const char *upcl_version(void);

/* ========== Session Management ========== */

/**
 * Create a new collection session
 * @param config Configuration for the session
 * @return Session handle or NULL on error
 */
upcl_session_t upcl_session_create(const upcl_config_t *config);

/**
 * Start data collection
 * @param session Session handle
 * @return 0 on success, negative error code on failure
 */
int upcl_session_start(upcl_session_t session);

/**
 * Stop data collection
 * @param session Session handle
 * @return 0 on success, negative error code on failure
 */
int upcl_session_stop(upcl_session_t session);

/**
 * Pause data collection
 * @param session Session handle
 * @return 0 on success, negative error code on failure
 */
int upcl_session_pause(upcl_session_t session);

/**
 * Resume data collection
 * @param session Session handle
 * @return 0 on success, negative error code on failure
 */
int upcl_session_resume(upcl_session_t session);

/**
 * Reset session counters
 * @param session Session handle
 * @return 0 on success, negative error code on failure
 */
int upcl_session_reset(upcl_session_t session);

/**
 * Destroy session and free resources
 * @param session Session handle
 */
void upcl_session_destroy(upcl_session_t session);

/* ========== Data Access ========== */

/**
 * Register callback for real-time processing
 * @param session Session handle
 * @param callback Callback function
 * @param ctx User context passed to callback
 * @return 0 on success, negative error code on failure
 */
int upcl_session_set_callback(upcl_session_t session, 
                             upcl_sample_callback_t callback,
                             void *ctx);

/**
 * Read collected samples
 * @param session Session handle
 * @param samples Buffer to store samples
 * @param max_samples Maximum number of samples to read
 * @param nr_samples Actual number of samples read
 * @return 0 on success, negative error code on failure
 */
int upcl_session_read(upcl_session_t session, 
                     upcl_sample_t *samples,
                     uint32_t max_samples,
                     uint32_t *nr_samples);

/**
 * Poll for new data with timeout
 * @param session Session handle
 * @param timeout_ms Timeout in milliseconds (-1 for infinite)
 * @return Number of new samples available, negative error code on failure
 */
int upcl_session_poll(upcl_session_t session, int timeout_ms);

/* ========== Data Export ========== */

/**
 * Export collected data to file
 * @param session Session handle
 * @param filename Output filename
 * @param format Export format
 * @return 0 on success, negative error code on failure
 */
int upcl_session_export(upcl_session_t session,
                       const char *filename,
                       upcl_format_t format);

/**
 * Export data with custom options
 * @param session Session handle
 * @param filename Output filename
 * @param format Export format
 * @param options Format-specific options (JSON string)
 * @return 0 on success, negative error code on failure
 */
int upcl_session_export_ex(upcl_session_t session,
                          const char *filename,
                          upcl_format_t format,
                          const char *options);

/**
 * Stream data to file descriptor
 * @param session Session handle
 * @param fd File descriptor
 * @param format Export format
 * @return 0 on success, negative error code on failure
 */
int upcl_session_stream(upcl_session_t session,
                       int fd,
                       upcl_format_t format);

/* ========== Statistics and Information ========== */

/**
 * Get session statistics
 * @param session Session handle
 * @param stats Statistics structure to fill
 * @return 0 on success, negative error code on failure
 */
int upcl_session_get_stats(upcl_session_t session,
                          upcl_stats_t *stats);

/**
 * Get platform information
 * @param info Platform info structure to fill
 * @return 0 on success, negative error code on failure
 */
int upcl_get_platform_info(upcl_platform_info_t *info);

/**
 * Check if a collection method is supported
 * @param method UPCL_METHOD_* flag
 * @return 1 if supported, 0 if not supported
 */
int upcl_method_supported(uint32_t method);

/**
 * Get available PMU events
 * @param events Array to store event IDs
 * @param nr_events Number of events (in/out)
 * @return 0 on success, negative error code on failure
 */
int upcl_pmu_available_events(uint32_t *events, uint32_t *nr_events);

/**
 * Get PMU event name
 * @param event Event ID
 * @param name Buffer for event name
 * @param len Buffer length
 * @return 0 on success, negative error code on failure
 */
int upcl_pmu_event_name(uint32_t event, char *name, size_t len);

/* ========== eBPF Support ========== */

/**
 * Load eBPF program
 * @param path Program path or builtin name
 * @param prog_fd Output program file descriptor
 * @return 0 on success, negative error code on failure
 */
int upcl_bpf_load_program(const char *path, int *prog_fd);

/**
 * Attach eBPF program to kernel probe
 * @param prog_fd Program file descriptor
 * @param func_name Kernel function name
 * @return Probe file descriptor on success, negative error code on failure
 */
int upcl_bpf_attach_kprobe(int prog_fd, const char *func_name);

/**
 * Attach eBPF program to user probe
 * @param prog_fd Program file descriptor
 * @param binary Binary path
 * @param func_name Function name
 * @return Probe file descriptor on success, negative error code on failure
 */
int upcl_bpf_attach_uprobe(int prog_fd, const char *binary, 
                          const char *func_name);

/**
 * Attach eBPF program to tracepoint
 * @param prog_fd Program file descriptor
 * @param category Tracepoint category
 * @param name Tracepoint name
 * @return Tracepoint file descriptor on success, negative error code on failure
 */
int upcl_bpf_attach_tracepoint(int prog_fd, const char *category,
                              const char *name);

/**
 * Detach eBPF program
 * @param attach_fd Attachment file descriptor
 * @return 0 on success, negative error code on failure
 */
int upcl_bpf_detach(int attach_fd);

/* ========== Utility Functions ========== */

/**
 * Convert error code to string
 * @param error Error code
 * @return Error string
 */
const char *upcl_error_string(int error);

/**
 * Get number of online CPUs
 * @return Number of CPUs
 */
int upcl_get_cpu_count(void);

/**
 * Set CPU affinity for collection
 * @param session Session handle
 * @param cpu_list Array of CPU numbers
 * @param nr_cpus Number of CPUs in list
 * @return 0 on success, negative error code on failure
 */
int upcl_session_set_affinity(upcl_session_t session,
                             const int *cpu_list,
                             int nr_cpus);

/**
 * Enable/disable specific events
 * @param session Session handle
 * @param events Bitmask of UPCL_DATA_* to enable/disable
 * @param enable True to enable, false to disable
 * @return 0 on success, negative error code on failure
 */
int upcl_session_control_events(upcl_session_t session,
                               uint32_t events,
                               bool enable);

/* ========== Advanced Features ========== */

/**
 * Create custom export formatter
 * @param name Formatter name
 * @param init_func Initialization function
 * @param write_func Write function
 * @param finish_func Finalization function
 * @return Format ID on success, negative error code on failure
 */
int upcl_register_format(const char *name,
                        void *(*init_func)(const char *options),
                        int (*write_func)(void *ctx, const upcl_sample_t *sample),
                        int (*finish_func)(void *ctx));

/**
 * Set custom filter function
 * @param session Session handle
 * @param filter_func Filter function (return 1 to keep sample, 0 to drop)
 * @param ctx User context
 * @return 0 on success, negative error code on failure
 */
int upcl_session_set_filter(upcl_session_t session,
                           int (*filter_func)(const upcl_sample_t *sample, void *ctx),
                           void *ctx);

/**
 * Trigger manual sample
 * @param session Session handle
 * @return 0 on success, negative error code on failure
 */
int upcl_session_trigger_sample(upcl_session_t session);

/**
 * Get raw ring buffer access (advanced users)
 * @param session Session handle
 * @param cpu CPU number
 * @param base Output base address
 * @param size Output size
 * @return 0 on success, negative error code on failure
 */
int upcl_session_get_ringbuf(upcl_session_t session,
                            int cpu,
                            void **base,
                            size_t *size);

#ifdef __cplusplus
}
#endif

#endif /* _UPCL_H */