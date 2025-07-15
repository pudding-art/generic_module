/*
 * Universal Performance Collection Library (UPCL)
 * eBPF implementation and programs
 */

#include "upcl.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

/* eBPF program for function tracing */
const char *bpf_func_trace_prog = "\
#include <linux/bpf.h>\n\
#include <linux/ptrace.h>\n\
#include <bpf/bpf_helpers.h>\n\
#include <bpf/bpf_tracing.h>\n\
\n\
struct trace_event {\n\
    __u64 timestamp;\n\
    __u64 ip;\n\
    __u32 pid;\n\
    __u32 cpu;\n\
    __u64 duration;\n\
    char comm[16];\n\
};\n\
\n\
struct {\n\
    __uint(type, BPF_MAP_TYPE_RINGBUF);\n\
    __uint(max_entries, 256 * 1024);\n\
} trace_rb SEC(\".maps\");\n\
\n\
struct {\n\
    __uint(type, BPF_MAP_TYPE_HASH);\n\
    __uint(max_entries, 10240);\n\
    __type(key, __u64);\n\
    __type(value, __u64);\n\
} start_time SEC(\".maps\");\n\
\n\
SEC(\"kprobe/generic_entry\")\n\
int trace_func_entry(struct pt_regs *ctx)\n\
{\n\
    __u64 pid_tgid = bpf_get_current_pid_tgid();\n\
    __u64 ts = bpf_ktime_get_ns();\n\
    \n\
    bpf_map_update_elem(&start_time, &pid_tgid, &ts, BPF_ANY);\n\
    return 0;\n\
}\n\
\n\
SEC(\"kretprobe/generic_return\")\n\
int trace_func_return(struct pt_regs *ctx)\n\
{\n\
    __u64 pid_tgid = bpf_get_current_pid_tgid();\n\
    __u64 *start_ts, duration;\n\
    struct trace_event *e;\n\
    \n\
    start_ts = bpf_map_lookup_elem(&start_time, &pid_tgid);\n\
    if (!start_ts)\n\
        return 0;\n\
    \n\
    e = bpf_ringbuf_reserve(&trace_rb, sizeof(*e), 0);\n\
    if (!e)\n\
        return 0;\n\
    \n\
    duration = bpf_ktime_get_ns() - *start_ts;\n\
    \n\
    e->timestamp = bpf_ktime_get_ns();\n\
    e->ip = PT_REGS_IP(ctx);\n\
    e->pid = pid_tgid >> 32;\n\
    e->cpu = bpf_get_smp_processor_id();\n\
    e->duration = duration;\n\
    bpf_get_current_comm(&e->comm, sizeof(e->comm));\n\
    \n\
    bpf_ringbuf_submit(e, 0);\n\
    bpf_map_delete_elem(&start_time, &pid_tgid);\n\
    \n\
    return 0;\n\
}\n\
\n\
char LICENSE[] SEC(\"license\") = \"GPL\";\n\
";

/* eBPF program for hardware event sampling */
const char *bpf_hw_sample_prog = "\
#include <linux/bpf.h>\n\
#include <linux/perf_event.h>\n\
#include <bpf/bpf_helpers.h>\n\
#include <bpf/bpf_tracing.h>\n\
\n\
struct hw_sample {\n\
    __u64 timestamp;\n\
    __u64 ip;\n\
    __u64 addr;\n\
    __u64 cpu_cycles;\n\
    __u64 instructions;\n\
    __u64 cache_misses;\n\
    __u32 pid;\n\
    __u32 cpu;\n\
};\n\
\n\
struct {\n\
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);\n\
    __uint(key_size, sizeof(int));\n\
    __uint(value_size, sizeof(__u32));\n\
    __uint(max_entries, 128);\n\
} hw_events SEC(\".maps\");\n\
\n\
struct {\n\
    __uint(type, BPF_MAP_TYPE_RINGBUF);\n\
    __uint(max_entries, 256 * 1024);\n\
} hw_samples SEC(\".maps\");\n\
\n\
SEC(\"perf_event\")\n\
int on_hw_event(struct bpf_perf_event_data *ctx)\n\
{\n\
    struct hw_sample *sample;\n\
    \n\
    sample = bpf_ringbuf_reserve(&hw_samples, sizeof(*sample), 0);\n\
    if (!sample)\n\
        return 0;\n\
    \n\
    sample->timestamp = bpf_ktime_get_ns();\n\
    sample->ip = ctx->regs.ip;\n\
    sample->addr = ctx->addr;\n\
    sample->pid = bpf_get_current_pid_tgid() >> 32;\n\
    sample->cpu = bpf_get_smp_processor_id();\n\
    \n\
    /* Read hardware counters */\n\
    bpf_perf_event_read_value(&hw_events, ctx->cpu, \n\
                             &sample->cpu_cycles, sizeof(__u64));\n\
    \n\
    bpf_ringbuf_submit(sample, 0);\n\
    return 0;\n\
}\n\
\n\
char LICENSE[] SEC(\"license\") = \"GPL\";\n\
";

/* Load and compile eBPF program */
int upcl_bpf_load_program(const char *path, int *prog_fd)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int fd;
    
    if (!path || !prog_fd)
        return UPCL_ERROR_INVALID_PARAM;
    
    /* Load BPF object from file or use built-in program */
    if (strcmp(path, "builtin:func_trace") == 0) {
        /* Use built-in function trace program */
        /* This would compile the program from source */
        /* For simplicity, return error here */
        return UPCL_ERROR_NOT_SUPPORTED;
    }
    
    /* Load from file */
    obj = bpf_object__open_file(path, NULL);
    if (libbpf_get_error(obj))
        return UPCL_ERROR_IO;
    
    /* Load programs */
    if (bpf_object__load(obj)) {
        bpf_object__close(obj);
        return UPCL_ERROR_IO;
    }
    
    /* Get first program */
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        bpf_object__close(obj);
        return UPCL_ERROR_IO;
    }
    
    fd = bpf_program__fd(prog);
    if (fd < 0) {
        bpf_object__close(obj);
        return UPCL_ERROR_IO;
    }
    
    *prog_fd = fd;
    return UPCL_SUCCESS;
}

/* Attach eBPF program to kernel probe */
int upcl_bpf_attach_kprobe(int prog_fd, const char *func_name)
{
    char buf[256];
    int kprobe_fd;
    
    if (prog_fd < 0 || !func_name)
        return UPCL_ERROR_INVALID_PARAM;
    
    /* Create kprobe event */
    snprintf(buf, sizeof(buf), "p:kprobes/%s %s", func_name, func_name);
    
    int fd = open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY);
    if (fd < 0)
        return UPCL_ERROR_NO_PERMISSION;
    
    if (write(fd, buf, strlen(buf)) < 0) {
        close(fd);
        return UPCL_ERROR_IO;
    }
    close(fd);
    
    /* Attach BPF program to kprobe */
    snprintf(buf, sizeof(buf), 
             "/sys/kernel/debug/tracing/events/kprobes/%s/id", func_name);
    
    fd = open(buf, O_RDONLY);
    if (fd < 0)
        return UPCL_ERROR_IO;
    
    if (read(fd, buf, sizeof(buf)) < 0) {
        close(fd);
        return UPCL_ERROR_IO;
    }
    close(fd);
    
    int event_id = atoi(buf);
    
    struct perf_event_attr attr = {
        .type = PERF_TYPE_TRACEPOINT,
        .config = event_id,
        .sample_type = PERF_SAMPLE_RAW,
        .sample_period = 1,
        .wakeup_events = 1,
    };
    
    kprobe_fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
    if (kprobe_fd < 0)
        return UPCL_ERROR_NO_PERMISSION;
    
    if (ioctl(kprobe_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
        close(kprobe_fd);
        return UPCL_ERROR_IO;
    }
    
    if (ioctl(kprobe_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
        close(kprobe_fd);
        return UPCL_ERROR_IO;
    }
    
    return kprobe_fd;
}

/* Attach eBPF program to user probe */
int upcl_bpf_attach_uprobe(int prog_fd, const char *binary, 
                          const char *func_name)
{
    char buf[512];
    int uprobe_fd;
    
    if (prog_fd < 0 || !binary || !func_name)
        return UPCL_ERROR_INVALID_PARAM;
    
    /* Create uprobe event */
    snprintf(buf, sizeof(buf), "p:uprobes/%s %s:%s", 
             func_name, binary, func_name);
    
    int fd = open("/sys/kernel/debug/tracing/uprobe_events", O_WRONLY);
    if (fd < 0)
        return UPCL_ERROR_NO_PERMISSION;
    
    if (write(fd, buf, strlen(buf)) < 0) {
        close(fd);
        return UPCL_ERROR_IO;
    }
    close(fd);
    
    /* Similar attachment as kprobe */
    /* ... implementation ... */
    
    return UPCL_SUCCESS;
}

/* eBPF-based session operations */
struct upcl_bpf_session {
    struct bpf_object *obj;
    struct bpf_map *ringbuf;
    struct ring_buffer *rb;
    int prog_fd;
};

/* Callback for ring buffer */
static int handle_bpf_event(void *ctx, void *data, size_t size)
{
    struct upcl_session *session = ctx;
    struct trace_event {
        uint64_t timestamp;
        uint64_t ip;
        uint32_t pid;
        uint32_t cpu;
        uint64_t duration;
        char comm[16];
    } *e = data;
    
    /* Convert to upcl_sample format */
    struct upcl_sample sample = {
        .timestamp = e->timestamp,
        .cpu = e->cpu,
        .pid = e->pid,
        .ip = e->ip,
    };
    
    /* Call user callback */
    if (session->callback) {
        session->callback(&sample, session->callback_ctx);
    }
    
    return 0;
}

/* Platform-specific eBPF programs for Intel */
#ifdef UPCL_ARCH_X86
const char *bpf_intel_lbr_prog = "\
#include <linux/bpf.h>\n\
#include <bpf/bpf_helpers.h>\n\
\n\
/* Intel LBR (Last Branch Record) sampling */\n\
struct lbr_entry {\n\
    __u64 from;\n\
    __u64 to;\n\
    __u64 flags;\n\
};\n\
\n\
struct {\n\
    __uint(type, BPF_MAP_TYPE_ARRAY);\n\
    __uint(max_entries, 32);\n\
    __type(key, __u32);\n\
    __type(value, struct lbr_entry);\n\
} lbr_entries SEC(\".maps\");\n\
\n\
SEC(\"perf_event\")\n\
int sample_lbr(struct bpf_perf_event_data *ctx)\n\
{\n\
    /* Read LBR entries from MSRs */\n\
    /* This requires special kernel support */\n\
    return 0;\n\
}\n\
\n\
char LICENSE[] SEC(\"license\") = \"GPL\";\n\
";
#endif

/* Platform-specific eBPF programs for AMD */
#ifdef UPCL_ARCH_X86
const char *bpf_amd_ibs_prog = "\
#include <linux/bpf.h>\n\
#include <bpf/bpf_helpers.h>\n\
\n\
/* AMD IBS (Instruction-Based Sampling) */\n\
struct ibs_sample {\n\
    __u64 ibs_op_rip;\n\
    __u64 ibs_op_data;\n\
    __u64 ibs_op_data2;\n\
    __u64 ibs_op_data3;\n\
    __u64 ibs_dc_linear;\n\
    __u64 ibs_dc_phys;\n\
};\n\
\n\
struct {\n\
    __uint(type, BPF_MAP_TYPE_RINGBUF);\n\
    __uint(max_entries, 256 * 1024);\n\
} ibs_samples SEC(\".maps\");\n\
\n\
SEC(\"perf_event\")\n\
int sample_ibs(struct bpf_perf_event_data *ctx)\n\
{\n\
    /* Process AMD IBS data */\n\
    return 0;\n\
}\n\
\n\
char LICENSE[] SEC(\"license\") = \"GPL\";\n\
";
#endif

/* Platform-specific eBPF programs for ARM */
#ifdef UPCL_ARCH_ARM
const char *bpf_arm_spe_prog = "\
#include <linux/bpf.h>\n\
#include <bpf/bpf_helpers.h>\n\
\n\
/* ARM SPE (Statistical Profiling Extension) */\n\
struct spe_sample {\n\
    __u64 timestamp;\n\
    __u64 virt_addr;\n\
    __u64 phys_addr;\n\
    __u64 context;\n\
    __u32 type;\n\
    __u32 latency;\n\
};\n\
\n\
struct {\n\
    __uint(type, BPF_MAP_TYPE_RINGBUF);\n\
    __uint(max_entries, 256 * 1024);\n\
} spe_samples SEC(\".maps\");\n\
\n\
SEC(\"perf_event\")\n\
int sample_spe(struct bpf_perf_event_data *ctx)\n\
{\n\
    /* Process ARM SPE data */\n\
    return 0;\n\
}\n\
\n\
char LICENSE[] SEC(\"license\") = \"GPL\";\n\
";
#endif