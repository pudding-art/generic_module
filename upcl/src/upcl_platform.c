/*
 * Universal Performance Collection Library (UPCL)
 * Platform detection and initialization
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include "upcl_internal.h"

/* Global log level */
int g_upcl_log_level = UPCL_LOG_LEVEL_INFO;

/* Parse /proc/cpuinfo */
static int parse_cpuinfo(upcl_platform_info_t *info)
{
    FILE *fp;
    char line[256];
    char *p;
    int cpu_count = 0;
    
    fp = fopen("/proc/cpuinfo", "r");
    if (!fp)
        return UPCL_ERROR_IO;
    
    while (fgets(line, sizeof(line), fp)) {
        /* Remove trailing newline */
        p = strchr(line, '\n');
        if (p)
            *p = '\0';
        
        /* Find the colon separator */
        p = strchr(line, ':');
        if (!p)
            continue;
        *p++ = '\0';
        
        /* Skip whitespace */
        while (*p && isspace(*p))
            p++;
        
        /* Architecture-specific parsing */
#ifdef __x86_64__
        if (strstr(line, "vendor_id")) {
            strncpy(info->vendor, p, sizeof(info->vendor) - 1);
        } else if (strstr(line, "model name")) {
            strncpy(info->model, p, sizeof(info->model) - 1);
        } else if (strstr(line, "cpu family")) {
            info->family = atoi(p);
        } else if (strstr(line, "model")) {
            info->model_id = atoi(p);
        } else if (strstr(line, "stepping")) {
            info->stepping = atoi(p);
        } else if (strstr(line, "cpu cores")) {
            info->nr_cores = atoi(p);
        } else if (strstr(line, "siblings")) {
            info->nr_threads = atoi(p);
        } else if (strstr(line, "flags")) {
            strncpy(info->feature_string, p, sizeof(info->feature_string) - 1);
        }
#elif defined(__aarch64__)
        if (strstr(line, "CPU implementer")) {
            int implementer = strtol(p, NULL, 0);
            switch (implementer) {
            case 0x41: strcpy(info->vendor, "ARM"); break;
            case 0x42: strcpy(info->vendor, "Broadcom"); break;
            case 0x43: strcpy(info->vendor, "Cavium"); break;
            case 0x44: strcpy(info->vendor, "DEC"); break;
            case 0x4e: strcpy(info->vendor, "Nvidia"); break;
            case 0x50: strcpy(info->vendor, "APM"); break;
            case 0x51: strcpy(info->vendor, "Qualcomm"); break;
            case 0x53: strcpy(info->vendor, "Samsung"); break;
            case 0x56: strcpy(info->vendor, "Marvell"); break;
            case 0x69: strcpy(info->vendor, "Intel"); break;
            default: strcpy(info->vendor, "Unknown"); break;
            }
        } else if (strstr(line, "CPU architecture")) {
            info->family = atoi(p);
        } else if (strstr(line, "CPU variant")) {
            info->model_id = strtol(p, NULL, 0);
        } else if (strstr(line, "CPU revision")) {
            info->stepping = atoi(p);
        } else if (strstr(line, "Features")) {
            strncpy(info->feature_string, p, sizeof(info->feature_string) - 1);
        }
#endif
        
        if (strstr(line, "processor")) {
            cpu_count++;
        }
    }
    
    fclose(fp);
    
    info->nr_cpus = cpu_count;
    
    return UPCL_SUCCESS;
}

/* Detect CPU features */
static void detect_cpu_features(upcl_platform_info_t *info)
{
#ifdef __x86_64__
    uint32_t eax, ebx, ecx, edx;
    
    /* Basic CPUID information */
    upcl_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    
    /* Check features */
    if (edx & (1 << 4))  info->features |= (1ULL << 0);  /* TSC */
    if (edx & (1 << 5))  info->features |= (1ULL << 1);  /* MSR */
    if (ecx & (1 << 0))  info->features |= (1ULL << 2);  /* SSE3 */
    if (ecx & (1 << 9))  info->features |= (1ULL << 3);  /* SSSE3 */
    if (ecx & (1 << 19)) info->features |= (1ULL << 4);  /* SSE4.1 */
    if (ecx & (1 << 20)) info->features |= (1ULL << 5);  /* SSE4.2 */
    if (ecx & (1 << 28)) info->features |= (1ULL << 6);  /* AVX */
    
    /* Extended features */
    upcl_cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    if (ebx & (1 << 5))  info->features |= (1ULL << 7);  /* AVX2 */
    if (ebx & (1 << 16)) info->features |= (1ULL << 8);  /* AVX512F */
    
    /* Check for Intel-specific features */
    if (strstr(info->vendor, "Intel")) {
        /* Performance monitoring */
        upcl_cpuid(0xa, 0, &eax, &ebx, &ecx, &edx);
        if (eax & 0xff) {
            info->features |= (1ULL << 16);  /* PMU version */
            
            /* Check for PEBS */
            if (ebx & (1 << 0))
                info->features |= (1ULL << 17);  /* PEBS */
        }
        
        /* Check for Intel PT */
        upcl_cpuid(0x14, 0, &eax, &ebx, &ecx, &edx);
        if (eax & 0x1)
            info->features |= (1ULL << 18);  /* Intel PT */
    }
    
    /* Check for AMD-specific features */
    if (strstr(info->vendor, "AMD")) {
        /* Extended CPUID */
        upcl_cpuid(0x80000001, 0, &eax, &ebx, &ecx, &edx);
        
        /* IBS support */
        if (ecx & (1 << 10))
            info->features |= (1ULL << 32);  /* IBS */
    }
    
#elif defined(__aarch64__)
    /* Parse feature string for ARM features */
    if (strstr(info->feature_string, "pmu"))
        info->features |= (1ULL << 0);  /* PMU */
    if (strstr(info->feature_string, "spe"))
        info->features |= (1ULL << 1);  /* SPE */
    if (strstr(info->feature_string, "sve"))
        info->features |= (1ULL << 2);  /* SVE */
    if (strstr(info->feature_string, "sve2"))
        info->features |= (1ULL << 3);  /* SVE2 */
#endif
}

/* Detect architecture */
static void detect_architecture(upcl_platform_info_t *info)
{
#if defined(__x86_64__)
    info->arch = UPCL_ARCH_X86_64;
#elif defined(__aarch64__)
    info->arch = UPCL_ARCH_ARM64;
#elif defined(__riscv) && __riscv_xlen == 64
    info->arch = UPCL_ARCH_RISCV64;
#elif defined(__powerpc64__)
    info->arch = UPCL_ARCH_PPC64;
#else
    info->arch = UPCL_ARCH_UNKNOWN;
#endif
}

/* Platform detection main function */
int upcl_platform_detect(upcl_platform_info_t *info)
{
    int ret;
    
    if (!info)
        return UPCL_ERROR_INVALID_PARAM;
    
    memset(info, 0, sizeof(*info));
    
    /* Detect architecture */
    detect_architecture(info);
    
    /* Parse /proc/cpuinfo */
    ret = parse_cpuinfo(info);
    if (ret < 0)
        return ret;
    
    /* Detect CPU features */
    detect_cpu_features(info);
    
    /* Fallback values */
    if (info->nr_cpus == 0)
        info->nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    
    if (info->nr_cores == 0)
        info->nr_cores = info->nr_cpus;
    
    if (info->nr_threads == 0)
        info->nr_threads = info->nr_cpus;
    
    /* Log platform information */
    upcl_log_info("Platform: %s %s (family %d, model %d, stepping %d)\n",
                  info->vendor, info->model,
                  info->family, info->model_id, info->stepping);
    upcl_log_info("CPUs: %d cores, %d threads total\n",
                  info->nr_cores, info->nr_threads);
    upcl_log_debug("Features: 0x%lx\n", info->features);
    
    /* Initialize platform-specific features */
#ifdef __x86_64__
    if (strstr(info->vendor, "Intel"))
        return upcl_platform_init_intel();
    else if (strstr(info->vendor, "AMD"))
        return upcl_platform_init_amd();
#elif defined(__aarch64__)
    return upcl_platform_init_arm();
#endif
    
    return UPCL_SUCCESS;
}

/* Check if method is supported */
int upcl_method_supported(uint32_t method)
{
    switch (method) {
    case UPCL_METHOD_PERF:
        /* perf_events is always available on Linux */
        return 1;
        
    case UPCL_METHOD_EBPF:
        /* Check for eBPF support */
        {
            int fd = open("/sys/kernel/debug/tracing/events", O_RDONLY);
            if (fd >= 0) {
                close(fd);
                return 1;
            }
        }
        return 0;
        
    case UPCL_METHOD_KMOD:
        /* Check if our kernel module is loaded */
        {
            int fd = open("/dev/upcl", O_RDONLY);
            if (fd >= 0) {
                close(fd);
                return 1;
            }
        }
        return 0;
        
    case UPCL_METHOD_PMU:
        /* PMU is supported if perf_events works */
        return 1;
        
    default:
        return 0;
    }
}

/* Get available PMU events */
int upcl_pmu_available_events(uint32_t *events, uint32_t *nr_events)
{
    uint32_t count = 0;
    uint32_t max_events;
    
    if (!events || !nr_events)
        return UPCL_ERROR_INVALID_PARAM;
    
    max_events = *nr_events;
    
    /* Basic hardware events always available */
    if (count < max_events) events[count++] = PERF_COUNT_HW_CPU_CYCLES;
    if (count < max_events) events[count++] = PERF_COUNT_HW_INSTRUCTIONS;
    if (count < max_events) events[count++] = PERF_COUNT_HW_CACHE_REFERENCES;
    if (count < max_events) events[count++] = PERF_COUNT_HW_CACHE_MISSES;
    if (count < max_events) events[count++] = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
    if (count < max_events) events[count++] = PERF_COUNT_HW_BRANCH_MISSES;
    if (count < max_events) events[count++] = PERF_COUNT_HW_BUS_CYCLES;
    
    /* Software events */
    if (count < max_events) events[count++] = PERF_COUNT_SW_CPU_CLOCK;
    if (count < max_events) events[count++] = PERF_COUNT_SW_TASK_CLOCK;
    if (count < max_events) events[count++] = PERF_COUNT_SW_PAGE_FAULTS;
    if (count < max_events) events[count++] = PERF_COUNT_SW_CONTEXT_SWITCHES;
    if (count < max_events) events[count++] = PERF_COUNT_SW_CPU_MIGRATIONS;
    
    *nr_events = count;
    return UPCL_SUCCESS;
}

/* Get PMU event name */
int upcl_pmu_event_name(uint32_t event, char *name, size_t len)
{
    const char *event_name = NULL;
    
    if (!name || len == 0)
        return UPCL_ERROR_INVALID_PARAM;
    
    switch (event) {
    /* Hardware events */
    case PERF_COUNT_HW_CPU_CYCLES:
        event_name = "cpu-cycles";
        break;
    case PERF_COUNT_HW_INSTRUCTIONS:
        event_name = "instructions";
        break;
    case PERF_COUNT_HW_CACHE_REFERENCES:
        event_name = "cache-references";
        break;
    case PERF_COUNT_HW_CACHE_MISSES:
        event_name = "cache-misses";
        break;
    case PERF_COUNT_HW_BRANCH_INSTRUCTIONS:
        event_name = "branch-instructions";
        break;
    case PERF_COUNT_HW_BRANCH_MISSES:
        event_name = "branch-misses";
        break;
    case PERF_COUNT_HW_BUS_CYCLES:
        event_name = "bus-cycles";
        break;
    case PERF_COUNT_HW_STALLED_CYCLES_FRONTEND:
        event_name = "stalled-cycles-frontend";
        break;
    case PERF_COUNT_HW_STALLED_CYCLES_BACKEND:
        event_name = "stalled-cycles-backend";
        break;
        
    /* Software events */
    case PERF_COUNT_SW_CPU_CLOCK:
        event_name = "cpu-clock";
        break;
    case PERF_COUNT_SW_TASK_CLOCK:
        event_name = "task-clock";
        break;
    case PERF_COUNT_SW_PAGE_FAULTS:
        event_name = "page-faults";
        break;
    case PERF_COUNT_SW_CONTEXT_SWITCHES:
        event_name = "context-switches";
        break;
    case PERF_COUNT_SW_CPU_MIGRATIONS:
        event_name = "cpu-migrations";
        break;
    case PERF_COUNT_SW_PAGE_FAULTS_MIN:
        event_name = "minor-faults";
        break;
    case PERF_COUNT_SW_PAGE_FAULTS_MAJ:
        event_name = "major-faults";
        break;
    case PERF_COUNT_SW_ALIGNMENT_FAULTS:
        event_name = "alignment-faults";
        break;
    case PERF_COUNT_SW_EMULATION_FAULTS:
        event_name = "emulation-faults";
        break;
        
    default:
        event_name = "unknown";
        break;
    }
    
    strncpy(name, event_name, len - 1);
    name[len - 1] = '\0';
    
    return UPCL_SUCCESS;
}