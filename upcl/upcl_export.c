/*
 * Universal Performance Collection Library (UPCL)
 * Data export implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <zlib.h>
#include "upcl_internal.h"

/* JSON exporter context */
struct json_exporter_ctx {
    FILE *fp;
    gzFile gzfp;
    bool compress;
    bool first_sample;
    uint64_t sample_count;
};

/* CSV exporter context */
struct csv_exporter_ctx {
    FILE *fp;
    gzFile gzfp;
    bool compress;
    bool header_written;
};

/* Binary exporter context */
struct binary_exporter_ctx {
    int fd;
    gzFile gzfp;
    bool compress;
    uint32_t version;
};

/* JSON exporter functions */
static int json_init(void **ctx, const char *path, bool compress)
{
    struct json_exporter_ctx *jctx;
    
    jctx = calloc(1, sizeof(*jctx));
    if (!jctx)
        return UPCL_ERROR_NO_MEMORY;
    
    jctx->compress = compress;
    jctx->first_sample = true;
    
    if (compress) {
        jctx->gzfp = gzopen(path, "wb");
        if (!jctx->gzfp) {
            free(jctx);
            return UPCL_ERROR_IO;
        }
        gzprintf(jctx->gzfp, "{\n  \"version\": \"%s\",\n", upcl_version());
        gzprintf(jctx->gzfp, "  \"timestamp\": %ld,\n", time(NULL));
        gzprintf(jctx->gzfp, "  \"samples\": [\n");
    } else {
        jctx->fp = fopen(path, "w");
        if (!jctx->fp) {
            free(jctx);
            return UPCL_ERROR_IO;
        }
        fprintf(jctx->fp, "{\n  \"version\": \"%s\",\n", upcl_version());
        fprintf(jctx->fp, "  \"timestamp\": %ld,\n", time(NULL));
        fprintf(jctx->fp, "  \"samples\": [\n");
    }
    
    *ctx = jctx;
    return UPCL_SUCCESS;
}

static int json_write(void *ctx, const upcl_sample_t *sample)
{
    struct json_exporter_ctx *jctx = ctx;
    
    if (!jctx->first_sample) {
        if (jctx->compress)
            gzprintf(jctx->gzfp, ",\n");
        else
            fprintf(jctx->fp, ",\n");
    }
    jctx->first_sample = false;
    
    if (jctx->compress) {
        gzprintf(jctx->gzfp, "    {\n");
        gzprintf(jctx->gzfp, "      \"timestamp\": %lu,\n", sample->timestamp);
        gzprintf(jctx->gzfp, "      \"cpu\": %u,\n", sample->cpu);
        gzprintf(jctx->gzfp, "      \"pid\": %u,\n", sample->pid);
        gzprintf(jctx->gzfp, "      \"tid\": %u,\n", sample->tid);
        gzprintf(jctx->gzfp, "      \"ip\": \"0x%lx\",\n", sample->ip);
        
        if (sample->cpu_cycles)
            gzprintf(jctx->gzfp, "      \"cpu_cycles\": %lu,\n", sample->cpu_cycles);
        if (sample->instructions)
            gzprintf(jctx->gzfp, "      \"instructions\": %lu,\n", sample->instructions);
        if (sample->cache_references)
            gzprintf(jctx->gzfp, "      \"cache_references\": %lu,\n", sample->cache_references);
        if (sample->cache_misses)
            gzprintf(jctx->gzfp, "      \"cache_misses\": %lu,\n", sample->cache_misses);
        if (sample->branch_instructions)
            gzprintf(jctx->gzfp, "      \"branches\": %lu,\n", sample->branch_instructions);
        if (sample->branch_misses)
            gzprintf(jctx->gzfp, "      \"branch_misses\": %lu,\n", sample->branch_misses);
        
        /* IPC calculation */
        if (sample->instructions && sample->cpu_cycles) {
            double ipc = (double)sample->instructions / sample->cpu_cycles;
            gzprintf(jctx->gzfp, "      \"ipc\": %.4f,\n", ipc);
        }
        
        /* Cache miss rate */
        if (sample->cache_references && sample->cache_misses) {
            double miss_rate = (double)sample->cache_misses / sample->cache_references;
            gzprintf(jctx->gzfp, "      \"cache_miss_rate\": %.4f,\n", miss_rate);
        }
        
        gzprintf(jctx->gzfp, "      \"period\": %lu\n", sample->period);
        gzprintf(jctx->gzfp, "    }");
    } else {
        fprintf(jctx->fp, "    {\n");
        fprintf(jctx->fp, "      \"timestamp\": %lu,\n", sample->timestamp);
        fprintf(jctx->fp, "      \"cpu\": %u,\n", sample->cpu);
        fprintf(jctx->fp, "      \"pid\": %u,\n", sample->pid);
        fprintf(jctx->fp, "      \"tid\": %u,\n", sample->tid);
        fprintf(jctx->fp, "      \"ip\": \"0x%lx\",\n", sample->ip);
        
        if (sample->cpu_cycles)
            fprintf(jctx->fp, "      \"cpu_cycles\": %lu,\n", sample->cpu_cycles);
        if (sample->instructions)
            fprintf(jctx->fp, "      \"instructions\": %lu,\n", sample->instructions);
        if (sample->cache_references)
            fprintf(jctx->fp, "      \"cache_references\": %lu,\n", sample->cache_references);
        if (sample->cache_misses)
            fprintf(jctx->fp, "      \"cache_misses\": %lu,\n", sample->cache_misses);
        if (sample->branch_instructions)
            fprintf(jctx->fp, "      \"branches\": %lu,\n", sample->branch_instructions);
        if (sample->branch_misses)
            fprintf(jctx->fp, "      \"branch_misses\": %lu,\n", sample->branch_misses);
        
        /* IPC calculation */
        if (sample->instructions && sample->cpu_cycles) {
            double ipc = (double)sample->instructions / sample->cpu_cycles;
            fprintf(jctx->fp, "      \"ipc\": %.4f,\n", ipc);
        }
        
        /* Cache miss rate */
        if (sample->cache_references && sample->cache_misses) {
            double miss_rate = (double)sample->cache_misses / sample->cache_references;
            fprintf(jctx->fp, "      \"cache_miss_rate\": %.4f,\n", miss_rate);
        }
        
        fprintf(jctx->fp, "      \"period\": %lu\n", sample->period);
        fprintf(jctx->fp, "    }");
    }
    
    jctx->sample_count++;
    return UPCL_SUCCESS;
}

static int json_flush(void *ctx)
{
    struct json_exporter_ctx *jctx = ctx;
    
    if (jctx->compress)
        gzflush(jctx->gzfp, Z_SYNC_FLUSH);
    else
        fflush(jctx->fp);
    
    return UPCL_SUCCESS;
}

static int json_finish(void *ctx)
{
    struct json_exporter_ctx *jctx = ctx;
    
    if (jctx->compress) {
        gzprintf(jctx->gzfp, "\n  ],\n");
        gzprintf(jctx->gzfp, "  \"total_samples\": %lu\n", jctx->sample_count);
        gzprintf(jctx->gzfp, "}\n");
        gzclose(jctx->gzfp);
    } else {
        fprintf(jctx->fp, "\n  ],\n");
        fprintf(jctx->fp, "  \"total_samples\": %lu\n", jctx->sample_count);
        fprintf(jctx->fp, "}\n");
        fclose(jctx->fp);
    }
    
    return UPCL_SUCCESS;
}

static void json_destroy(void *ctx)
{
    free(ctx);
}

/* CSV exporter functions */
static int csv_init(void **ctx, const char *path, bool compress)
{
    struct csv_exporter_ctx *cctx;
    
    cctx = calloc(1, sizeof(*cctx));
    if (!cctx)
        return UPCL_ERROR_NO_MEMORY;
    
    cctx->compress = compress;
    
    if (compress) {
        cctx->gzfp = gzopen(path, "wb");
        if (!cctx->gzfp) {
            free(cctx);
            return UPCL_ERROR_IO;
        }
    } else {
        cctx->fp = fopen(path, "w");
        if (!cctx->fp) {
            free(cctx);
            return UPCL_ERROR_IO;
        }
    }
    
    *ctx = cctx;
    return UPCL_SUCCESS;
}

static int csv_write(void *ctx, const upcl_sample_t *sample)
{
    struct csv_exporter_ctx *cctx = ctx;
    
    /* Write header on first sample */
    if (!cctx->header_written) {
        const char *header = "timestamp,cpu,pid,tid,ip,cpu_cycles,instructions,"
                           "cache_references,cache_misses,branches,branch_misses,"
                           "page_faults,context_switches,ipc,cache_miss_rate\n";
        if (cctx->compress)
            gzprintf(cctx->gzfp, "%s", header);
        else
            fprintf(cctx->fp, "%s", header);
        cctx->header_written = true;
    }
    
    /* Calculate derived metrics */
    double ipc = 0.0;
    double cache_miss_rate = 0.0;
    
    if (sample->instructions && sample->cpu_cycles)
        ipc = (double)sample->instructions / sample->cpu_cycles;
    if (sample->cache_references && sample->cache_misses)
        cache_miss_rate = (double)sample->cache_misses / sample->cache_references;
    
    /* Write sample data */
    if (cctx->compress) {
        gzprintf(cctx->gzfp, "%lu,%u,%u,%u,0x%lx,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%.4f,%.4f\n",
                sample->timestamp, sample->cpu, sample->pid, sample->tid, sample->ip,
                sample->cpu_cycles, sample->instructions,
                sample->cache_references, sample->cache_misses,
                sample->branch_instructions, sample->branch_misses,
                sample->page_faults, sample->context_switches,
                ipc, cache_miss_rate);
    } else {
        fprintf(cctx->fp, "%lu,%u,%u,%u,0x%lx,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%.4f,%.4f\n",
                sample->timestamp, sample->cpu, sample->pid, sample->tid, sample->ip,
                sample->cpu_cycles, sample->instructions,
                sample->cache_references, sample->cache_misses,
                sample->branch_instructions, sample->branch_misses,
                sample->page_faults, sample->context_switches,
                ipc, cache_miss_rate);
    }
    
    return UPCL_SUCCESS;
}

static int csv_flush(void *ctx)
{
    struct csv_exporter_ctx *cctx = ctx;
    
    if (cctx->compress)
        gzflush(cctx->gzfp, Z_SYNC_FLUSH);
    else
        fflush(cctx->fp);
    
    return UPCL_SUCCESS;
}

static int csv_finish(void *ctx)
{
    struct csv_exporter_ctx *cctx = ctx;
    
    if (cctx->compress)
        gzclose(cctx->gzfp);
    else
        fclose(cctx->fp);
    
    return UPCL_SUCCESS;
}

static void csv_destroy(void *ctx)
{
    free(ctx);
}

/* Binary exporter functions */
static int binary_init(void **ctx, const char *path, bool compress)
{
    struct binary_exporter_ctx *bctx;
    struct {
        uint32_t magic;
        uint32_t version;
        uint64_t timestamp;
        uint32_t header_size;
        uint32_t sample_size;
    } header = {
        .magic = 0x5550434C,  /* 'UPCL' */
        .version = 1,
        .timestamp = time(NULL),
        .header_size = sizeof(header),
        .sample_size = sizeof(upcl_sample_t)
    };
    
    bctx = calloc(1, sizeof(*bctx));
    if (!bctx)
        return UPCL_ERROR_NO_MEMORY;
    
    bctx->compress = compress;
    bctx->version = 1;
    
    if (compress) {
        bctx->gzfp = gzopen(path, "wb");
        if (!bctx->gzfp) {
            free(bctx);
            return UPCL_ERROR_IO;
        }
        gzwrite(bctx->gzfp, &header, sizeof(header));
    } else {
        bctx->fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (bctx->fd < 0) {
            free(bctx);
            return UPCL_ERROR_IO;
        }
        write(bctx->fd, &header, sizeof(header));
    }
    
    *ctx = bctx;
    return UPCL_SUCCESS;
}

static int binary_write(void *ctx, const upcl_sample_t *sample)
{
    struct binary_exporter_ctx *bctx = ctx;
    
    if (bctx->compress) {
        gzwrite(bctx->gzfp, sample, sizeof(*sample));
    } else {
        write(bctx->fd, sample, sizeof(*sample));
    }
    
    return UPCL_SUCCESS;
}

static int binary_flush(void *ctx)
{
    struct binary_exporter_ctx *bctx = ctx;
    
    if (bctx->compress)
        gzflush(bctx->gzfp, Z_SYNC_FLUSH);
    else
        fsync(bctx->fd);
    
    return UPCL_SUCCESS;
}

static int binary_finish(void *ctx)
{
    struct binary_exporter_ctx *bctx = ctx;
    
    if (bctx->compress)
        gzclose(bctx->gzfp);
    else
        close(bctx->fd);
    
    return UPCL_SUCCESS;
}

static void binary_destroy(void *ctx)
{
    free(ctx);
}

/* Exporter table */
static struct {
    upcl_format_t format;
    int (*init)(void **ctx, const char *path, bool compress);
    int (*write)(void *ctx, const upcl_sample_t *sample);
    int (*flush)(void *ctx);
    int (*finish)(void *ctx);
    void (*destroy)(void *ctx);
} exporters[] = {
    {
        .format = UPCL_FORMAT_JSON,
        .init = json_init,
        .write = json_write,
        .flush = json_flush,
        .finish = json_finish,
        .destroy = json_destroy
    },
    {
        .format = UPCL_FORMAT_CSV,
        .init = csv_init,
        .write = csv_write,
        .flush = csv_flush,
        .finish = csv_finish,
        .destroy = csv_destroy
    },
    {
        .format = UPCL_FORMAT_BINARY,
        .init = binary_init,
        .write = binary_write,
        .flush = binary_flush,
        .finish = binary_finish,
        .destroy = binary_destroy
    }
};

/* Create exporter */
struct upcl_exporter *upcl_exporter_create(upcl_format_t format,
                                          const char *path,
                                          bool compress)
{
    struct upcl_exporter *exporter;
    int i, ret;
    
    /* Find exporter for format */
    for (i = 0; i < sizeof(exporters) / sizeof(exporters[0]); i++) {
        if (exporters[i].format == format)
            break;
    }
    
    if (i == sizeof(exporters) / sizeof(exporters[0]))
        return NULL;  /* Format not supported */
    
    exporter = calloc(1, sizeof(*exporter));
    if (!exporter)
        return NULL;
    
    exporter->format = format;
    exporter->init = exporters[i].init;
    exporter->write = exporters[i].write;
    exporter->flush = exporters[i].flush;
    exporter->finish = exporters[i].finish;
    exporter->destroy = exporters[i].destroy;
    
    /* Initialize exporter */
    ret = exporter->init(&exporter->ctx, path, compress);
    if (ret != UPCL_SUCCESS) {
        free(exporter);
        return NULL;
    }
    
    return exporter;
}

/* Destroy exporter */
void upcl_exporter_destroy(struct upcl_exporter *exporter)
{
    if (!exporter)
        return;
    
    if (exporter->ctx) {
        exporter->finish(exporter->ctx);
        exporter->destroy(exporter->ctx);
    }
    
    free(exporter);
}

/* Start exporter */
int upcl_exporter_start(struct upcl_exporter *exporter)
{
    /* Nothing to do for most exporters */
    return UPCL_SUCCESS;
}

/* Stop exporter */
int upcl_exporter_stop(struct upcl_exporter *exporter)
{
    if (!exporter)
        return UPCL_ERROR_INVALID_PARAM;
    
    return exporter->flush(exporter->ctx);
}

/* Write sample */
int upcl_exporter_write(struct upcl_exporter *exporter,
                       const upcl_sample_t *sample)
{
    if (!exporter || !sample)
        return UPCL_ERROR_INVALID_PARAM;
    
    return exporter->write(exporter->ctx, sample);
}

/* Flush exporter */
int upcl_exporter_flush(struct upcl_exporter *exporter)
{
    if (!exporter)
        return UPCL_ERROR_INVALID_PARAM;
    
    return exporter->flush(exporter->ctx);
}

/* Export session data */
int upcl_session_export(upcl_session_t session,
                       const char *filename,
                       upcl_format_t format)
{
    /* This would be implemented in the session to read all collected
     * data and write it using the exporter */
    return UPCL_SUCCESS;
}