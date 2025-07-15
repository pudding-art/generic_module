/*
 * Universal Performance Collection Library (UPCL)
 * Core implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include "upcl.h"
#include "upcl_internal.h"

/* Global library state */
static struct {
    bool initialized;
    pthread_mutex_t mutex;
    upcl_platform_info_t platform;
    struct list_head sessions;
    uint32_t nr_sessions;
} g_upcl_state = {
    .initialized = false,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
};

/* Internal session structure */
struct upcl_session {
    struct upcl_config config;
    
    /* State */
    enum {
        SESSION_STATE_CREATED = 0,
        SESSION_STATE_RUNNING,
        SESSION_STATE_PAUSED,
        SESSION_STATE_STOPPED
    } state;
    pthread_mutex_t mutex;
    
    /* Collection method handlers */
    struct {
        void *perf;
        void *ebpf;
        void *kmod;
    } handlers;
    
    /* Ring buffers */
    struct upcl_ringbuf **ringbufs;
    uint32_t nr_ringbufs;
    
    /* Reader threads */
    pthread_t *reader_threads;
    uint32_t nr_readers;
    volatile int active;
    
    /* Callback */
    upcl_sample_callback_t callback;
    void *callback_ctx;
    pthread_spinlock_t callback_lock;
    
    /* Filter */
    int (*filter_func)(const upcl_sample_t *sample, void *ctx);
    void *filter_ctx;
    
    /* Output */
    struct upcl_exporter *exporter;
    
    /* Statistics */
    struct upcl_stats stats;
    pthread_spinlock_t stats_lock;
    
    /* List node */
    struct list_head list;
};

/* Initialize the library */
int upcl_init(void)
{
    int ret;
    
    pthread_mutex_lock(&g_upcl_state.mutex);
    
    if (g_upcl_state.initialized) {
        pthread_mutex_unlock(&g_upcl_state.mutex);
        return UPCL_SUCCESS;
    }
    
    /* Detect platform */
    ret = upcl_platform_detect(&g_upcl_state.platform);
    if (ret < 0) {
        pthread_mutex_unlock(&g_upcl_state.mutex);
        return ret;
    }
    
    /* Initialize subsystems */
    ret = upcl_perf_init();
    if (ret < 0) {
        pthread_mutex_unlock(&g_upcl_state.mutex);
        return ret;
    }
    
    ret = upcl_ebpf_init();
    if (ret < 0) {
        upcl_perf_cleanup();
        pthread_mutex_unlock(&g_upcl_state.mutex);
        return ret;
    }
    
    /* Initialize session list */
    INIT_LIST_HEAD(&g_upcl_state.sessions);
    g_upcl_state.nr_sessions = 0;
    
    g_upcl_state.initialized = true;
    pthread_mutex_unlock(&g_upcl_state.mutex);
    
    upcl_log_info("UPCL initialized successfully on %s platform\n",
                  g_upcl_state.platform.vendor);
    
    return UPCL_SUCCESS;
}

/* Cleanup library resources */
void upcl_cleanup(void)
{
    struct upcl_session *session, *tmp;
    
    pthread_mutex_lock(&g_upcl_state.mutex);
    
    if (!g_upcl_state.initialized) {
        pthread_mutex_unlock(&g_upcl_state.mutex);
        return;
    }
    
    /* Destroy all sessions */
    list_for_each_entry_safe(session, tmp, &g_upcl_state.sessions, list) {
        list_del(&session->list);
        pthread_mutex_unlock(&g_upcl_state.mutex);
        upcl_session_destroy(session);
        pthread_mutex_lock(&g_upcl_state.mutex);
    }
    
    /* Cleanup subsystems */
    upcl_ebpf_cleanup();
    upcl_perf_cleanup();
    
    g_upcl_state.initialized = false;
    pthread_mutex_unlock(&g_upcl_state.mutex);
}

/* Get library version */
const char *upcl_version(void)
{
    return UPCL_VERSION_STRING;
}

/* Create a new collection session */
upcl_session_t upcl_session_create(const upcl_config_t *config)
{
    struct upcl_session *session;
    int ret;
    
    if (!config)
        return NULL;
    
    if (!g_upcl_state.initialized) {
        ret = upcl_init();
        if (ret < 0)
            return NULL;
    }
    
    session = calloc(1, sizeof(*session));
    if (!session)
        return NULL;
    
    /* Copy configuration */
    memcpy(&session->config, config, sizeof(*config));
    
    /* Duplicate string fields */
    if (config->output_path) {
        session->config.output_path = strdup(config->output_path);
        if (!session->config.output_path)
            goto err_free;
    }
    
    if (config->bpf_program_path) {
        session->config.bpf_program_path = strdup(config->bpf_program_path);
        if (!session->config.bpf_program_path)
            goto err_free_output;
    }
    
    /* Initialize state */
    session->state = SESSION_STATE_CREATED;
    pthread_mutex_init(&session->mutex, NULL);
    pthread_spin_init(&session->callback_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&session->stats_lock, PTHREAD_PROCESS_PRIVATE);
    
    /* Initialize collection methods */
    if (config->methods & UPCL_METHOD_PERF) {
        session->handlers.perf = upcl_perf_create(session, config);
        if (!session->handlers.perf)
            goto err_free_bpf;
    }
    
    if (config->methods & UPCL_METHOD_EBPF) {
        session->handlers.ebpf = upcl_ebpf_create(session, config);
        if (!session->handlers.ebpf)
            goto err_free_perf;
    }
    
    if (config->methods & UPCL_METHOD_KMOD) {
        session->handlers.kmod = upcl_kmod_create(session, config);
        if (!session->handlers.kmod)
            goto err_free_ebpf;
    }
    
    /* Create exporter */
    if (config->output_path) {
        session->exporter = upcl_exporter_create(config->output_format,
                                                config->output_path,
                                                config->compress_output);
        if (!session->exporter)
            goto err_free_kmod;
    }
    
    /* Add to global session list */
    pthread_mutex_lock(&g_upcl_state.mutex);
    list_add(&session->list, &g_upcl_state.sessions);
    g_upcl_state.nr_sessions++;
    pthread_mutex_unlock(&g_upcl_state.mutex);
    
    upcl_log_debug("Created session %p with methods 0x%x\n",
                   session, config->methods);
    
    return session;
    
err_free_kmod:
    if (session->handlers.kmod)
        upcl_kmod_destroy(session->handlers.kmod);
err_free_ebpf:
    if (session->handlers.ebpf)
        upcl_ebpf_destroy(session->handlers.ebpf);
err_free_perf:
    if (session->handlers.perf)
        upcl_perf_destroy(session->handlers.perf);
err_free_bpf:
    free(session->config.bpf_program_path);
err_free_output:
    free(session->config.output_path);
err_free:
    free(session);
    return NULL;
}

/* Start data collection */
int upcl_session_start(upcl_session_t session)
{
    int ret = UPCL_SUCCESS;
    int i;
    
    if (!session)
        return UPCL_ERROR_INVALID_PARAM;
    
    pthread_mutex_lock(&session->mutex);
    
    if (session->state == SESSION_STATE_RUNNING) {
        pthread_mutex_unlock(&session->mutex);
        return UPCL_SUCCESS;
    }
    
    if (session->state != SESSION_STATE_CREATED &&
        session->state != SESSION_STATE_STOPPED) {
        pthread_mutex_unlock(&session->mutex);
        return UPCL_ERROR_INVALID_PARAM;
    }
    
    /* Start collection methods */
    if (session->handlers.perf) {
        ret = upcl_perf_start(session->handlers.perf);
        if (ret < 0)
            goto err_unlock;
    }
    
    if (session->handlers.ebpf) {
        ret = upcl_ebpf_start(session->handlers.ebpf);
        if (ret < 0)
            goto err_stop_perf;
    }
    
    if (session->handlers.kmod) {
        ret = upcl_kmod_start(session->handlers.kmod);
        if (ret < 0)
            goto err_stop_ebpf;
    }
    
    /* Start reader threads */
    session->active = 1;
    if (session->nr_readers > 0) {
        for (i = 0; i < session->nr_readers; i++) {
            ret = pthread_create(&session->reader_threads[i], NULL,
                               upcl_reader_thread, session);
            if (ret != 0) {
                session->active = 0;
                /* Wait for started threads to finish */
                for (int j = 0; j < i; j++) {
                    pthread_join(session->reader_threads[j], NULL);
                }
                ret = UPCL_ERROR_NO_MEMORY;
                goto err_stop_kmod;
            }
        }
    }
    
    /* Start exporter if configured */
    if (session->exporter) {
        ret = upcl_exporter_start(session->exporter);
        if (ret < 0)
            goto err_stop_readers;
    }
    
    session->state = SESSION_STATE_RUNNING;
    pthread_mutex_unlock(&session->mutex);
    
    upcl_log_info("Session %p started successfully\n", session);
    return UPCL_SUCCESS;
    
err_stop_readers:
    session->active = 0;
    for (i = 0; i < session->nr_readers; i++) {
        pthread_join(session->reader_threads[i], NULL);
    }
err_stop_kmod:
    if (session->handlers.kmod)
        upcl_kmod_stop(session->handlers.kmod);
err_stop_ebpf:
    if (session->handlers.ebpf)
        upcl_ebpf_stop(session->handlers.ebpf);
err_stop_perf:
    if (session->handlers.perf)
        upcl_perf_stop(session->handlers.perf);
err_unlock:
    pthread_mutex_unlock(&session->mutex);
    return ret;
}

/* Stop data collection */
int upcl_session_stop(upcl_session_t session)
{
    int i;
    
    if (!session)
        return UPCL_ERROR_INVALID_PARAM;
    
    pthread_mutex_lock(&session->mutex);
    
    if (session->state != SESSION_STATE_RUNNING &&
        session->state != SESSION_STATE_PAUSED) {
        pthread_mutex_unlock(&session->mutex);
        return UPCL_SUCCESS;
    }
    
    /* Stop collection methods */
    if (session->handlers.perf)
        upcl_perf_stop(session->handlers.perf);
    
    if (session->handlers.ebpf)
        upcl_ebpf_stop(session->handlers.ebpf);
    
    if (session->handlers.kmod)
        upcl_kmod_stop(session->handlers.kmod);
    
    /* Stop reader threads */
    session->active = 0;
    pthread_mutex_unlock(&session->mutex);
    
    for (i = 0; i < session->nr_readers; i++) {
        pthread_join(session->reader_threads[i], NULL);
    }
    
    pthread_mutex_lock(&session->mutex);
    
    /* Stop exporter */
    if (session->exporter)
        upcl_exporter_stop(session->exporter);
    
    session->state = SESSION_STATE_STOPPED;
    pthread_mutex_unlock(&session->mutex);
    
    upcl_log_info("Session %p stopped\n", session);
    return UPCL_SUCCESS;
}

/* Destroy session */
void upcl_session_destroy(upcl_session_t session)
{
    if (!session)
        return;
    
    /* Stop if running */
    if (session->state == SESSION_STATE_RUNNING ||
        session->state == SESSION_STATE_PAUSED) {
        upcl_session_stop(session);
    }
    
    /* Remove from global list */
    pthread_mutex_lock(&g_upcl_state.mutex);
    list_del(&session->list);
    g_upcl_state.nr_sessions--;
    pthread_mutex_unlock(&g_upcl_state.mutex);
    
    /* Destroy handlers */
    if (session->handlers.perf)
        upcl_perf_destroy(session->handlers.perf);
    
    if (session->handlers.ebpf)
        upcl_ebpf_destroy(session->handlers.ebpf);
    
    if (session->handlers.kmod)
        upcl_kmod_destroy(session->handlers.kmod);
    
    /* Destroy exporter */
    if (session->exporter)
        upcl_exporter_destroy(session->exporter);
    
    /* Free ring buffers */
    for (int i = 0; i < session->nr_ringbufs; i++) {
        upcl_ringbuf_destroy(session->ringbufs[i]);
    }
    free(session->ringbufs);
    free(session->reader_threads);
    
    /* Free config strings */
    free(session->config.output_path);
    free(session->config.bpf_program_path);
    free(session->config.filter.comm_filter);
    free(session->config.filter.cpu_list);
    
    /* Destroy locks */
    pthread_mutex_destroy(&session->mutex);
    pthread_spin_destroy(&session->callback_lock);
    pthread_spin_destroy(&session->stats_lock);
    
    upcl_log_debug("Destroyed session %p\n", session);
    free(session);
}

/* Set callback for real-time processing */
int upcl_session_set_callback(upcl_session_t session,
                             upcl_sample_callback_t callback,
                             void *ctx)
{
    if (!session)
        return UPCL_ERROR_INVALID_PARAM;
    
    pthread_spin_lock(&session->callback_lock);
    session->callback = callback;
    session->callback_ctx = ctx;
    pthread_spin_unlock(&session->callback_lock);
    
    return UPCL_SUCCESS;
}

/* Process sample through callback and filters */
int upcl_session_process_sample(struct upcl_session *session,
                               const upcl_sample_t *sample)
{
    int ret = 0;
    
    /* Apply filter if set */
    if (session->filter_func) {
        if (!session->filter_func(sample, session->filter_ctx))
            return 0;  /* Sample filtered out */
    }
    
    /* Call user callback */
    pthread_spin_lock(&session->callback_lock);
    if (session->callback) {
        ret = session->callback(sample, session->callback_ctx);
    }
    pthread_spin_unlock(&session->callback_lock);
    
    /* Export sample */
    if (session->exporter) {
        upcl_exporter_write(session->exporter, sample);
    }
    
    /* Update statistics */
    pthread_spin_lock(&session->stats_lock);
    session->stats.samples_collected++;
    pthread_spin_unlock(&session->stats_lock);
    
    return ret;
}

/* Get session statistics */
int upcl_session_get_stats(upcl_session_t session, upcl_stats_t *stats)
{
    if (!session || !stats)
        return UPCL_ERROR_INVALID_PARAM;
    
    pthread_spin_lock(&session->stats_lock);
    memcpy(stats, &session->stats, sizeof(*stats));
    pthread_spin_unlock(&session->stats_lock);
    
    /* Get handler-specific stats */
    if (session->handlers.perf)
        upcl_perf_get_stats(session->handlers.perf, stats);
    
    if (session->handlers.ebpf)
        upcl_ebpf_get_stats(session->handlers.ebpf, stats);
    
    return UPCL_SUCCESS;
}

/* Get platform information */
int upcl_get_platform_info(upcl_platform_info_t *info)
{
    if (!info)
        return UPCL_ERROR_INVALID_PARAM;
    
    if (!g_upcl_state.initialized) {
        int ret = upcl_init();
        if (ret < 0)
            return ret;
    }
    
    memcpy(info, &g_upcl_state.platform, sizeof(*info));
    return UPCL_SUCCESS;
}

/* Error string conversion */
const char *upcl_error_string(int error)
{
    switch (error) {
    case UPCL_SUCCESS:
        return "Success";
    case UPCL_ERROR_INVALID_PARAM:
        return "Invalid parameter";
    case UPCL_ERROR_NO_MEMORY:
        return "Out of memory";
    case UPCL_ERROR_NO_PERMISSION:
        return "Permission denied";
    case UPCL_ERROR_NOT_SUPPORTED:
        return "Not supported";
    case UPCL_ERROR_DEVICE_BUSY:
        return "Device busy";
    case UPCL_ERROR_IO:
        return "I/O error";
    case UPCL_ERROR_OVERFLOW:
        return "Buffer overflow";
    case UPCL_ERROR_NOT_FOUND:
        return "Not found";
    case UPCL_ERROR_TIMEOUT:
        return "Timeout";
    default:
        return "Unknown error";
    }
}

/* Get CPU count */
int upcl_get_cpu_count(void)
{
    return sysconf(_SC_NPROCESSORS_ONLN);
}