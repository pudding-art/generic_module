/*
 * Universal Performance Collection Library (UPCL)
 * Perf events subsystem implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include "upcl_internal.h"

/* Perf event group */
struct perf_event_group {
    int leader_fd;
    int *member_fds;
    int nr_members;
    struct perf_event_attr *attrs;
    void *mmap_base;
    size_t mmap_size;
    int cpu;
};

/* Perf handle structure */
struct upcl_perf_handle {
    struct upcl_session *session;
    struct upcl_config config;
    
    /* Event groups per CPU */
    struct perf_event_group **groups;
    int nr_groups;
    
    /* Reader thread */
    pthread_t reader_thread;
    volatile int active;
    
    /* Ring buffer */
    struct upcl_ringbuf *ringbuf;
    
    /* Statistics */
    uint64_t samples_processed;
    uint64_t samples_lost;
    uint64_t wakeups;
};

/* Helper: perf_event_open syscall */
static long perf_event_open(struct perf_event_attr *attr,
                           pid_t pid, int cpu, int group_fd,
                           unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* Parse perf sample data */
static int parse_perf_sample(struct perf_event_mmap_page *header,
                           void *data, size_t size,
                           struct perf_event_attr *attr,
                           upcl_sample_t *sample)
{
    uint64_t *ptr = data;
    uint64_t type = attr->sample_type;
    
    memset(sample, 0, sizeof(*sample));
    
    /* Parse based on sample_type bits */
    if (type & PERF_SAMPLE_IDENTIFIER) {
        ptr++;  /* Skip identifier */
    }
    
    if (type & PERF_SAMPLE_IP) {
        sample->ip = *ptr++;
    }
    
    if (type & PERF_SAMPLE_TID) {
        uint32_t *tid_ptr = (uint32_t *)ptr;
        sample->pid = tid_ptr[0];
        sample->tid = tid_ptr[1];
        ptr++;
    }
    
    if (type & PERF_SAMPLE_TIME) {
        sample->timestamp = *ptr++;
    }
    
    if (type & PERF_SAMPLE_ADDR) {
        sample->addr = *ptr++;
    }
    
    if (type & PERF_SAMPLE_ID) {
        ptr++;  /* Skip ID */
    }
    
    if (type & PERF_SAMPLE_STREAM_ID) {
        ptr++;  /* Skip stream ID */
    }
    
    if (type & PERF_SAMPLE_CPU) {
        uint32_t *cpu_ptr = (uint32_t *)ptr;
        sample->cpu = cpu_ptr[0];
        ptr++;
    }
    
    if (type & PERF_SAMPLE_PERIOD) {
        sample->period = *ptr++;
    }
    
    if (type & PERF_SAMPLE_READ) {
        /* Read format data - parse based on read_format */
        if (attr->read_format & PERF_FORMAT_GROUP) {
            uint64_t nr = *ptr++;
            /* Skip time_enabled/running if present */
            if (attr->read_format & PERF_FORMAT_TOTAL_TIME_ENABLED)
                ptr++;
            if (attr->read_format & PERF_FORMAT_TOTAL_TIME_RUNNING)
                ptr++;
            
            /* Read counter values */
            for (uint64_t i = 0; i < nr && i < 16; i++) {
                uint64_t value = *ptr++;
                /* Map to sample fields based on event type */
                switch (i) {
                case 0: sample->cpu_cycles = value; break;
                case 1: sample->instructions = value; break;
                case 2: sample->cache_references = value; break;
                case 3: sample->cache_misses = value; break;
                case 4: sample->branch_instructions = value; break;
                case 5: sample->branch_misses = value; break;
                }
                
                if (attr->read_format & PERF_FORMAT_ID)
                    ptr++;  /* Skip ID */
            }
        } else {
            sample->cpu_cycles = *ptr++;
        }
    }
    
    if (type & PERF_SAMPLE_CALLCHAIN) {
        uint64_t nr = *ptr++;
        sample->nr_stack_entries = (nr > 128) ? 128 : nr;
        if (sample->nr_stack_entries > 0) {
            sample->stack = malloc(sample->nr_stack_entries * sizeof(uint64_t));
            if (sample->stack) {
                memcpy(sample->stack, ptr, sample->nr_stack_entries * sizeof(uint64_t));
            }
        }
        ptr += nr;
    }
    
    if (type & PERF_SAMPLE_RAW) {
        uint32_t raw_size = *(uint32_t *)ptr;
        ptr = (uint64_t *)((char *)ptr + sizeof(uint32_t));
        sample->custom_data = malloc(raw_size);
        if (sample->custom_data) {
            memcpy(sample->custom_data, ptr, raw_size);
            sample->custom_data_size = raw_size;
        }
        ptr = (uint64_t *)((char *)ptr + raw_size);
    }
    
    if (type & PERF_SAMPLE_BRANCH_STACK) {
        /* Branch stack parsing for LBR */
        struct perf_branch_entry {
            uint64_t from;
            uint64_t to;
            uint64_t misc;
        } *entries;
        
        uint64_t nr = *ptr++;
        if (nr > 0) {
            entries = (struct perf_branch_entry *)ptr;
            /* Store in platform-specific data */
            sample->arch_data.intel.lbr_entries = nr;
            sample->arch_data.intel.lbr_stack = malloc(nr * sizeof(*entries));
            if (sample->arch_data.intel.lbr_stack) {
                memcpy(sample->arch_data.intel.lbr_stack, entries, nr * sizeof(*entries));
            }
        }
    }
    
    if (type & PERF_SAMPLE_WEIGHT) {
        sample->weight = *ptr++;
    }
    
    if (type & PERF_SAMPLE_DATA_SRC) {
        sample->data_src = *ptr++;
    }
    
    return 0;
}

/* Process ring buffer data */
static void process_ring_buffer(struct upcl_perf_handle *handle,
                               struct perf_event_group *group)
{
    struct perf_event_mmap_page *header = group->mmap_base;
    uint64_t data_head, data_tail;
    void *data_base;
    
    if (!header)
        return;
    
    data_base = (char *)header + header->data_offset;
    data_head = header->data_head;
    data_tail = header->data_tail;
    upcl_rmb();
    
    while (data_tail < data_head) {
        struct perf_event_header *event_header;
        upcl_sample_t sample;
        
        event_header = (struct perf_event_header *)((char *)data_base +
                                                   (data_tail & (header->data_size - 1)));
        
        switch (event_header->type) {
        case PERF_RECORD_SAMPLE:
            if (parse_perf_sample(header, event_header + 1,
                                event_header->size - sizeof(*event_header),
                                &group->attrs[0], &sample) == 0) {
                upcl_session_process_sample(handle->session, &sample);
                handle->samples_processed++;
                
                /* Free allocated memory */
                free(sample.stack);
                free(sample.custom_data);
                free(sample.arch_data.intel.lbr_stack);
            }
            break;
            
        case PERF_RECORD_LOST:
            {
                struct {
                    struct perf_event_header header;
                    uint64_t id;
                    uint64_t lost;
                } *lost = (void *)event_header;
                handle->samples_lost += lost->lost;
            }
            break;
            
        case PERF_RECORD_THROTTLE:
        case PERF_RECORD_UNTHROTTLE:
            /* Handle throttling events */
            break;
        }
        
        data_tail += event_header->size;
    }
    
    upcl_wmb();
    header->data_tail = data_tail;
}

/* Reader thread for perf events */
static void *perf_reader_thread(void *arg)
{
    struct upcl_perf_handle *handle = arg;
    struct pollfd *pollfds;
    int i, ret;
    
    pollfds = calloc(handle->nr_groups, sizeof(*pollfds));
    if (!pollfds)
        return NULL;
    
    /* Setup poll descriptors */
    for (i = 0; i < handle->nr_groups; i++) {
        pollfds[i].fd = handle->groups[i]->leader_fd;
        pollfds[i].events = POLLIN;
    }
    
    while (handle->active) {
        ret = poll(pollfds, handle->nr_groups, 100);  /* 100ms timeout */
        if (ret < 0) {
            if (errno != EINTR)
                break;
            continue;
        }
        
        if (ret == 0)  /* Timeout */
            continue;
        
        /* Process available data */
        for (i = 0; i < handle->nr_groups; i++) {
            if (pollfds[i].revents & POLLIN) {
                process_ring_buffer(handle, handle->groups[i]);
                handle->wakeups++;
            }
        }
    }
    
    free(pollfds);
    return NULL;
}

/* Create perf event group */
static struct perf_event_group *create_event_group(struct upcl_perf_handle *handle,
                                                  int cpu)
{
    struct perf_event_group *group;
    struct perf_event_attr attr;
    int i, fd;
    
    group = calloc(1, sizeof(*group));
    if (!group)
        return NULL;
    
    group->cpu = cpu;
    group->leader_fd = -1;
    
    /* Count number of events */
    group->nr_members = __builtin_popcount(handle->config.data_types & 0x3F);
    if (group->nr_members == 0)
        group->nr_members = 1;  /* At least CPU cycles */
    
    group->member_fds = calloc(group->nr_members, sizeof(int));
    group->attrs = calloc(group->nr_members, sizeof(struct perf_event_attr));
    if (!group->member_fds || !group->attrs)
        goto err_free;
    
    /* Initialize all FDs to -1 */
    for (i = 0; i < group->nr_members; i++)
        group->member_fds[i] = -1;
    
    /* Base attribute configuration */
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.disabled = 1;
    attr.inherit = handle->config.inherit;
    attr.exclude_kernel = handle->config.exclude_kernel;
    attr.exclude_user = handle->config.exclude_user;
    attr.exclude_hv = handle->config.exclude_hv;
    attr.exclude_idle = handle->config.exclude_idle;
    
    /* Sampling configuration */
    if (handle->config.sample_freq > 0) {
        attr.freq = 1;
        attr.sample_freq = handle->config.sample_freq;
    } else if (handle->config.sample_period > 0) {
        attr.sample_period = handle->config.sample_period;
    } else {
        attr.sample_period = 100000;  /* Default */
    }
    
    /* Sample types */
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | 
                      PERF_SAMPLE_TIME | PERF_SAMPLE_CPU |
                      PERF_SAMPLE_PERIOD | PERF_SAMPLE_READ;
    
    if (handle->config.data_types & UPCL_DATA_STACK_TRACE)
        attr.sample_type |= PERF_SAMPLE_CALLCHAIN;
    
    /* Read format for group reading */
    attr.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID |
                      PERF_FORMAT_TOTAL_TIME_ENABLED |
                      PERF_FORMAT_TOTAL_TIME_RUNNING;
    
    /* Platform-specific configuration */
#ifdef __x86_64__
    if (handle->config.platform.intel.precise_ip) {
        attr.precise_ip = handle->config.platform.intel.precise_ip;
    }
    if (handle->config.platform.intel.pebs) {
        attr.sample_type |= PERF_SAMPLE_WEIGHT | PERF_SAMPLE_DATA_SRC;
    }
    if (handle->config.platform.intel.lbr) {
        attr.sample_type |= PERF_SAMPLE_BRANCH_STACK;
        attr.branch_sample_type = PERF_SAMPLE_BRANCH_ANY;
    }
#endif
    
    /* Create events */
    i = 0;
    
    /* Leader event - CPU cycles */
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    memcpy(&group->attrs[i], &attr, sizeof(attr));
    
    fd = perf_event_open(&attr, handle->config.pid, cpu, -1, 0);
    if (fd < 0) {
        upcl_log_error("Failed to create perf event: %s\n", strerror(errno));
        goto err_free;
    }
    group->leader_fd = group->member_fds[i] = fd;
    i++;
    
    /* Additional events as group members */
    attr.disabled = 0;  /* Only leader is disabled */
    
    if (i < group->nr_members && (handle->config.data_types & UPCL_DATA_INSTRUCTIONS)) {
        attr.config = PERF_COUNT_HW_INSTRUCTIONS;
        memcpy(&group->attrs[i], &attr, sizeof(attr));
        fd = perf_event_open(&attr, handle->config.pid, cpu, group->leader_fd, 0);
        if (fd >= 0) {
            group->member_fds[i] = fd;
            i++;
        }
    }
    
    if (i < group->nr_members && (handle->config.data_types & UPCL_DATA_CACHE_REFS)) {
        attr.config = PERF_COUNT_HW_CACHE_REFERENCES;
        memcpy(&group->attrs[i], &attr, sizeof(attr));
        fd = perf_event_open(&attr, handle->config.pid, cpu, group->leader_fd, 0);
        if (fd >= 0) {
            group->member_fds[i] = fd;
            i++;
        }
    }
    
    if (i < group->nr_members && (handle->config.data_types & UPCL_DATA_CACHE_MISSES)) {
        attr.config = PERF_COUNT_HW_CACHE_MISSES;
        memcpy(&group->attrs[i], &attr, sizeof(attr));
        fd = perf_event_open(&attr, handle->config.pid, cpu, group->leader_fd, 0);
        if (fd >= 0) {
            group->member_fds[i] = fd;
            i++;
        }
    }
    
    if (i < group->nr_members && (handle->config.data_types & UPCL_DATA_BRANCHES)) {
        attr.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
        memcpy(&group->attrs[i], &attr, sizeof(attr));
        fd = perf_event_open(&attr, handle->config.pid, cpu, group->leader_fd, 0);
        if (fd >= 0) {
            group->member_fds[i] = fd;
            i++;
        }
    }
    
    if (i < group->nr_members && (handle->config.data_types & UPCL_DATA_BRANCH_MISSES)) {
        attr.config = PERF_COUNT_HW_BRANCH_MISSES;
        memcpy(&group->attrs[i], &attr, sizeof(attr));
        fd = perf_event_open(&attr, handle->config.pid, cpu, group->leader_fd, 0);
        if (fd >= 0) {
            group->member_fds[i] = fd;
            i++;
        }
    }
    
    /* Update actual number of events */
    group->nr_members = i;
    
    /* Map ring buffer */
    group->mmap_size = (handle->config.mmap_pages + 1) * sysconf(_SC_PAGESIZE);
    group->mmap_base = mmap(NULL, group->mmap_size,
                           PROT_READ | PROT_WRITE, MAP_SHARED,
                           group->leader_fd, 0);
    if (group->mmap_base == MAP_FAILED) {
        upcl_log_error("Failed to mmap perf buffer: %s\n", strerror(errno));
        goto err_close;
    }
    
    return group;
    
err_close:
    for (i = 0; i < group->nr_members; i++) {
        if (group->member_fds[i] >= 0)
            close(group->member_fds[i]);
    }
err_free:
    free(group->member_fds);
    free(group->attrs);
    free(group);
    return NULL;
}

/* Destroy event group */
static void destroy_event_group(struct perf_event_group *group)
{
    int i;
    
    if (!group)
        return;
    
    if (group->mmap_base && group->mmap_base != MAP_FAILED)
        munmap(group->mmap_base, group->mmap_size);
    
    for (i = 0; i < group->nr_members; i++) {
        if (group->member_fds[i] >= 0)
            close(group->member_fds[i]);
    }
    
    free(group->member_fds);
    free(group->attrs);
    free(group);
}

/* Initialize perf subsystem */
int upcl_perf_init(void)
{
    /* Check perf_event_paranoid */
    FILE *fp = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
    if (fp) {
        int paranoid;
        if (fscanf(fp, "%d", &paranoid) == 1 && paranoid > 2) {
            upcl_log_warn("perf_event_paranoid=%d may require root\n", paranoid);
        }
        fclose(fp);
    }
    
    return UPCL_SUCCESS;
}

/* Cleanup perf subsystem */
void upcl_perf_cleanup(void)
{
    /* Nothing to cleanup globally */
}

/* Create perf handle */
void *upcl_perf_create(struct upcl_session *session, const upcl_config_t *config)
{
    struct upcl_perf_handle *handle;
    int cpu, nr_cpus;
    int created = 0;
    
    handle = calloc(1, sizeof(*handle));
    if (!handle)
        return NULL;
    
    handle->session = session;
    memcpy(&handle->config, config, sizeof(*config));
    
    /* Create ring buffer */
    handle->ringbuf = upcl_ringbuf_create(config->buffer_size ?
                                         config->buffer_size : 1024 * 1024);
    if (!handle->ringbuf)
        goto err_free;
    
    /* Determine number of CPUs to monitor */
    nr_cpus = upcl_get_cpu_count();
    if (config->cpu_mask == 0)
        handle->config.cpu_mask = (1ULL << nr_cpus) - 1;
    
    /* Count active CPUs */
    handle->nr_groups = __builtin_popcountll(handle->config.cpu_mask & ((1ULL << nr_cpus) - 1));
    if (handle->nr_groups == 0)
        handle->nr_groups = 1;
    
    handle->groups = calloc(handle->nr_groups, sizeof(struct perf_event_group *));
    if (!handle->groups)
        goto err_ringbuf;
    
    /* Create event groups for each CPU */
    for (cpu = 0; cpu < nr_cpus && created < handle->nr_groups; cpu++) {
        if (!(handle->config.cpu_mask & (1ULL << cpu)))
            continue;
        
        handle->groups[created] = create_event_group(handle, cpu);
        if (handle->groups[created])
            created++;
    }
    
    if (created == 0) {
        upcl_log_error("Failed to create any perf event groups\n");
        goto err_groups;
    }
    
    handle->nr_groups = created;
    upcl_log_info("Created %d perf event groups\n", created);
    
    return handle;
    
err_groups:
    free(handle->groups);
err_ringbuf:
    upcl_ringbuf_destroy(handle->ringbuf);
err_free:
    free(handle);
    return NULL;
}

/* Destroy perf handle */
void upcl_perf_destroy(void *h)
{
    struct upcl_perf_handle *handle = h;
    int i;
    
    if (!handle)
        return;
    
    /* Stop if running */
    if (handle->active)
        upcl_perf_stop(handle);
    
    /* Destroy event groups */
    for (i = 0; i < handle->nr_groups; i++) {
        destroy_event_group(handle->groups[i]);
    }
    free(handle->groups);
    
    /* Destroy ring buffer */
    upcl_ringbuf_destroy(handle->ringbuf);
    
    free(handle);
}

/* Start perf collection */
int upcl_perf_start(void *h)
{
    struct upcl_perf_handle *handle = h;
    int i, ret;
    
    if (!handle || handle->active)
        return UPCL_ERROR_INVALID_PARAM;
    
    /* Start reader thread */
    handle->active = 1;
    ret = pthread_create(&handle->reader_thread, NULL,
                        perf_reader_thread, handle);
    if (ret != 0) {
        handle->active = 0;
        return UPCL_ERROR_NO_MEMORY;
    }
    
    /* Enable all event groups */
    for (i = 0; i < handle->nr_groups; i++) {
        ioctl(handle->groups[i]->leader_fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(handle->groups[i]->leader_fd, PERF_EVENT_IOC_ENABLE, 0);
    }
    
    upcl_log_debug("Started perf collection with %d groups\n", handle->nr_groups);
    return UPCL_SUCCESS;
}

/* Stop perf collection */
int upcl_perf_stop(void *h)
{
    struct upcl_perf_handle *handle = h;
    int i;
    
    if (!handle || !handle->active)
        return UPCL_ERROR_INVALID_PARAM;
    
    /* Disable all event groups */
    for (i = 0; i < handle->nr_groups; i++) {
        ioctl(handle->groups[i]->leader_fd, PERF_EVENT_IOC_DISABLE, 0);
    }
    
    /* Stop reader thread */
    handle->active = 0;
    pthread_join(handle->reader_thread, NULL);
    
    /* Process any remaining data */
    for (i = 0; i < handle->nr_groups; i++) {
        process_ring_buffer(handle, handle->groups[i]);
    }
    
    upcl_log_debug("Stopped perf collection\n");
    return UPCL_SUCCESS;
}

/* Get perf statistics */
int upcl_perf_get_stats(void *h, upcl_stats_t *stats)
{
    struct upcl_perf_handle *handle = h;
    
    if (!handle || !stats)
        return UPCL_ERROR_INVALID_PARAM;
    
    stats->samples_collected += handle->samples_processed;
    stats->samples_lost += handle->samples_lost;
    
    return UPCL_SUCCESS;
}