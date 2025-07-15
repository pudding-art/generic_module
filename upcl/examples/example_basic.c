/*
 * Universal Performance Collection Library (UPCL)
 * Basic usage example
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <time.h>
#include "upcl.h"

/* Global session for signal handler */
static upcl_session_t g_session = NULL;
static volatile int g_running = 1;

/* Signal handler for clean shutdown */
static void signal_handler(int sig)
{
    printf("\nStopping collection...\n");
    g_running = 0;
}

/* Sample callback for real-time processing */
static int sample_callback(const upcl_sample_t *sample, void *ctx)
{
    static uint64_t count = 0;
    static uint64_t last_print = 0;
    
    count++;
    
    /* Print summary every 10000 samples */
    if (count - last_print >= 10000) {
        printf("Processed %lu samples - Latest: CPU=%u PID=%u IPC=%.2f\n",
               count, sample->cpu, sample->pid,
               sample->instructions ? (double)sample->instructions / sample->cpu_cycles : 0.0);
        last_print = count;
    }
    
    return 0;
}

/* Workload function - matrix multiplication */
static void matrix_multiply(int size)
{
    double *a, *b, *c;
    int i, j, k;
    
    /* Allocate matrices */
    a = malloc(size * size * sizeof(double));
    b = malloc(size * size * sizeof(double));
    c = malloc(size * size * sizeof(double));
    
    if (!a || !b || !c) {
        free(a); free(b); free(c);
        return;
    }
    
    /* Initialize matrices */
    for (i = 0; i < size * size; i++) {
        a[i] = (double)rand() / RAND_MAX;
        b[i] = (double)rand() / RAND_MAX;
        c[i] = 0.0;
    }
    
    /* Matrix multiplication */
    for (i = 0; i < size; i++) {
        for (j = 0; j < size; j++) {
            for (k = 0; k < size; k++) {
                c[i * size + j] += a[i * size + k] * b[k * size + j];
            }
        }
    }
    
    /* Prevent optimization */
    volatile double sum = 0;
    for (i = 0; i < size * size; i++) {
        sum += c[i];
    }
    
    free(a); free(b); free(c);
}

/* Main function */
int main(int argc, char *argv[])
{
    upcl_config_t config;
    upcl_stats_t stats;
    upcl_platform_info_t platform;
    int ret;
    
    printf("=== UPCL Basic Example ===\n");
    printf("Library version: %s\n\n", upcl_version());
    
    /* Initialize library */
    ret = upcl_init();
    if (ret != UPCL_SUCCESS) {
        fprintf(stderr, "Failed to initialize UPCL: %s\n",
                upcl_error_string(ret));
        return 1;
    }
    
    /* Get platform information */
    ret = upcl_get_platform_info(&platform);
    if (ret == UPCL_SUCCESS) {
        printf("Platform: %s %s\n", platform.vendor, platform.model);
        printf("Architecture: ");
        switch (platform.arch) {
        case UPCL_ARCH_X86_64: printf("x86_64\n"); break;
        case UPCL_ARCH_ARM64: printf("ARM64\n"); break;
        default: printf("Unknown\n"); break;
        }
        printf("CPUs: %d\n\n", platform.nr_cpus);
    }
    
    /* Configure collection */
    memset(&config, 0, sizeof(config));
    config.methods = UPCL_METHOD_PERF;
    config.data_types = UPCL_DATA_CPU_CYCLES | 
                       UPCL_DATA_INSTRUCTIONS |
                       UPCL_DATA_CACHE_REFS |
                       UPCL_DATA_CACHE_MISSES |
                       UPCL_DATA_BRANCHES |
                       UPCL_DATA_BRANCH_MISSES;
    config.sample_freq = 1000;        /* 1 kHz sampling */
    config.cpu_mask = 0;              /* All CPUs */
    config.pid = -1;                  /* System-wide */
    config.mmap_pages = 128;          /* 128 pages per CPU */
    config.buffer_size = 4 * 1024 * 1024;  /* 4MB buffer */
    config.inherit = true;
    config.exclude_kernel = false;
    config.exclude_user = false;
    config.output_format = UPCL_FORMAT_JSON;
    config.output_path = "perf_data.json";
    
    /* Create session */
    g_session = upcl_session_create(&config);
    if (!g_session) {
        fprintf(stderr, "Failed to create session\n");
        return 1;
    }
    
    /* Set callback for real-time processing */
    ret = upcl_session_set_callback(g_session, sample_callback, NULL);
    if (ret != UPCL_SUCCESS) {
        fprintf(stderr, "Failed to set callback: %s\n",
                upcl_error_string(ret));
        goto cleanup;
    }
    
    /* Setup signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Start collection */
    ret = upcl_session_start(g_session);
    if (ret != UPCL_SUCCESS) {
        fprintf(stderr, "Failed to start collection: %s\n",
                upcl_error_string(ret));
        goto cleanup;
    }
    
    printf("Collection started. Running workload...\n");
    printf("Press Ctrl+C to stop.\n\n");
    
    /* Run workload */
    srand(time(NULL));
    while (g_running) {
        /* Matrix multiplication with different sizes */
        matrix_multiply(100);
        matrix_multiply(200);
        matrix_multiply(300);
        
        /* Brief pause */
        usleep(100000);  /* 100ms */
    }
    
    /* Stop collection */
    ret = upcl_session_stop(g_session);
    if (ret != UPCL_SUCCESS) {
        fprintf(stderr, "Failed to stop collection: %s\n",
                upcl_error_string(ret));
    }
    
    /* Get statistics */
    ret = upcl_session_get_stats(g_session, &stats);
    if (ret == UPCL_SUCCESS) {
        printf("\nCollection Statistics:\n");
        printf("  Samples collected: %lu\n", stats.samples_collected);
        printf("  Samples lost: %lu\n", stats.samples_lost);
        printf("  Bytes written: %lu\n", stats.bytes_written);
        printf("  CPU usage: %.2f%%\n", stats.cpu_usage);
        printf("  Memory usage: %.2f MB\n", stats.memory_usage_mb);
    }
    
    /* Export data */
    printf("\nExporting data to %s...\n", config.output_path);
    ret = upcl_session_export(g_session, config.output_path, config.output_format);
    if (ret == UPCL_SUCCESS) {
        printf("Data exported successfully.\n");
    } else {
        fprintf(stderr, "Failed to export data: %s\n",
                upcl_error_string(ret));
    }
    
    /* Also export as CSV for easy analysis */
    ret = upcl_session_export(g_session, "perf_data.csv", UPCL_FORMAT_CSV);
    if (ret == UPCL_SUCCESS) {
        printf("CSV data exported to perf_data.csv\n");
    }
    
cleanup:
    /* Cleanup */
    upcl_session_destroy(g_session);
    upcl_cleanup();
    
    printf("\nExample completed.\n");
    return 0;
}