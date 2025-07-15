# Universal Performance Collection Library (UPCL)

A comprehensive performance data collection library for Linux systems supporting multiple architectures (Intel, AMD, ARM) and collection methods (eBPF, perf_events, kernel modules).

## Features

- **Multi-Platform Support**: Intel (with PEBS/LBR), AMD (with IBS), ARM (with SPE)
- **Multiple Collection Methods**: eBPF, perf_events, kernel probes, hardware PMU
- **Flexible Data Types**: CPU cycles, instructions, cache metrics, branches, page faults, custom PMU events
- **Multiple Output Formats**: Binary, JSON, CSV, Protocol Buffers
- **Real-time Processing**: Callback-based sample processing for immediate analysis
- **AI/ML Ready**: Designed for feeding performance data to AI models for decision making
- **Kernel & User Space**: Works in both kernel modules and user applications

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    User Application                      │
├─────────────────────────────────────────────────────────┤
│                      UPCL API                           │
├──────────┬──────────┬──────────┬────────────┬──────────┤
│   eBPF   │   perf   │ kprobes  │    PMU     │ Platform │
│ Programs │  events  │ uprobes  │   Events   │ Specific │
├──────────┴──────────┴──────────┴────────────┴──────────┤
│                    Ring Buffer                          │
├─────────────────────────────────────────────────────────┤
│              Data Export (JSON/CSV/Binary)              │
└─────────────────────────────────────────────────────────┘
```

## Building

### Prerequisites

```bash
# Install dependencies
sudo apt-get install build-essential linux-headers-$(uname -r) \
                     libbpf-dev libelf-dev clang llvm

# For eBPF support
sudo apt-get install bpftool
```

### Build Library

```bash
make all
sudo make install
```

### Build Kernel Module (Optional)

```bash
make upcl.ko
sudo insmod upcl.ko
```

## Usage Examples

### Basic CPU Sampling

```c
#include <upcl.h>

// Initialize library
upcl_init();

// Configure collection
upcl_config_t config = {
    .methods = UPCL_METHOD_PERF,
    .data_types = UPCL_DATA_CPU_CYCLES | UPCL_DATA_INSTRUCTIONS,
    .sample_freq = 1000,  // 1 kHz
    .output_format = UPCL_FORMAT_JSON,
    .output_path = "perf_data.json"
};

// Create session
upcl_session_t session = upcl_session_create(&config);

// Start collection
upcl_session_start(session);

// ... your workload ...

// Stop and export
upcl_session_stop(session);
upcl_session_export(session, "results.json", UPCL_FORMAT_JSON);
upcl_session_destroy(session);
```

### Real-time Processing with Callbacks

```c
// Callback for processing samples
int process_sample(const upcl_sample_t *sample, void *ctx) {
    if (sample->cache_misses > threshold) {
        // Trigger page migration or other action
        migrate_pages(sample->pid, sample->addr);
    }
    return 0;
}

// Register callback
upcl_session_set_callback(session, process_sample, NULL);
```

### eBPF Function Tracing

```c
upcl_config_t config = {
    .methods = UPCL_METHOD_EBPF | UPCL_METHOD_KPROBE,
    .data_types = UPCL_DATA_FUNC_TRACE,
    .bpf_program_path = "trace_prog.bpf.c"
};

// Attach to kernel functions
int prog_fd;
upcl_bpf_load_program("trace_prog.bpf.c", &prog_fd);
upcl_bpf_attach_kprobe(prog_fd, "do_page_fault");
```

### Platform-Specific Features

#### Intel PEBS (Precise Event Based Sampling)

```c
config.platform.intel.precise_ip = 2;  // Enable PEBS
config.platform.intel.pebs = 1;
config.platform.intel.lbr = 1;         // Last Branch Records
```

#### AMD IBS (Instruction Based Sampling)

```c
config.platform.amd.ibs_fetch = 1;
config.platform.amd.ibs_op = 1;
```

#### ARM SPE (Statistical Profiling Extension)

```c
config.platform.arm.spe = 1;
```

## AI/ML Integration

The library is designed to feed performance data directly to AI models:

```c
// Collect comprehensive metrics for AI training
upcl_config_t config = {
    .data_types = UPCL_DATA_CPU_CYCLES | UPCL_DATA_INSTRUCTIONS |
                  UPCL_DATA_CACHE_REFS | UPCL_DATA_CACHE_MISSES |
                  UPCL_DATA_BRANCHES | UPCL_DATA_BRANCH_MISSES,
    .output_format = UPCL_FORMAT_PROTOBUF  // For TensorFlow
};

// Process samples for feature extraction
int ai_callback(const upcl_sample_t *sample, void *ctx) {
    float features[] = {
        (float)sample->instructions / sample->cpu_cycles,  // IPC
        (float)sample->cache_misses / sample->cache_references,
        (float)sample->branch_misses / sample->branch_instructions
    };
    
    // Feed to AI model
    ai_model_predict(features, 3);
    return 0;
}
```

## Kernel Module Usage

For kernel-space data collection:

```bash
# Load module
sudo insmod upcl.ko buffer_size_kb=2048

# Use via ioctl interface
int fd = open("/dev/upcl", O_RDWR);
ioctl(fd, UPCL_IOC_START_COLLECTION, &config);
```

## Performance Overhead

- Basic sampling: < 1% CPU overhead at 1kHz
- eBPF tracing: 2-5% depending on probe frequency
- Full PMU collection: 5-10% with all counters enabled

## Output Formats

### JSON Format
```json
{
  "timestamp": 1234567890,
  "samples": [
    {
      "cpu": 0,
      "pid": 1234,
      "ip": "0xffffffffa0000000",
      "cycles": 1000000,
      "instructions": 800000
    }
  ]
}
```

### CSV Format
```csv
timestamp,cpu,pid,ip,cycles,instructions,cache_misses
1234567890,0,1234,0xffffffffa0000000,1000000,800000,100
```

## Troubleshooting

### Permission Denied
- Run with sudo or adjust `/proc/sys/kernel/perf_event_paranoid`
- eBPF requires CAP_SYS_ADMIN capability

### High Overhead
- Reduce sampling frequency
- Limit data types collected
- Use targeted PID instead of system-wide

### Missing Samples
- Increase buffer size with `mmap_pages`
- Check for CPU throttling
- Verify kernel CONFIG_* options

## API Reference

See `upcl.h` for complete API documentation.


## Project Structure

```
upcl/
├── Makefile                    # Main build file
├── README.md                   # Project documentation
├── LICENSE                     # GPL v2 license
├── include/                    # Public headers
│   ├── upcl.h                 # Main API header
│   └── upcl_types.h           # Type definitions
├── src/                        # Source files
│   ├── upcl_internal.h        # Internal definitions
│   ├── upcl_core.c            # Core implementation
│   ├── upcl_perf.c            # Perf events subsystem
│   ├── upcl_ebpf.c            # eBPF subsystem
│   ├── upcl_platform.c        # Platform detection
│   ├── upcl_intel.c           # Intel-specific features
│   ├── upcl_amd.c             # AMD-specific features  
│   ├── upcl_arm.c             # ARM-specific features
│   ├── upcl_export.c          # Data export functions
│   ├── upcl_utils.c           # Utility functions
│   └── ebpf/                  # eBPF programs
│       ├── trace.bpf.c        # Function tracing
│       ├── sample.bpf.c       # Hardware sampling
│       └── probe.bpf.c        # Probe programs
├── kernel/                     # Kernel module
│   ├── Makefile               # Kernel module makefile
│   ├── upcl_module.c          # Main module
│   ├── upcl_kmod_ops.c        # Module operations
│   └── upcl_kmod.h            # Module header
├── examples/                   # Example programs
│   ├── example_basic.c        # Basic usage
│   ├── example_ebpf.c         # eBPF examples
│   ├── example_ai.c           # AI integration
│   └── example_kernel.c       # Kernel module usage
├── tests/                      # Test suite
│   ├── test_core.c            # Core tests
│   ├── test_perf.c            # Perf tests
│   ├── test_platform.c        # Platform tests
│   └── run_tests.sh           # Test runner
├── tools/                      # Utility tools
│   ├── upcl-stat              # Statistics tool
│   ├── upcl-record            # Recording tool
│   └── upcl-report            # Report generator
└── docs/                       # Documentation
    ├── API.md                 # API reference
    ├── INTERNALS.md           # Internal design
    └── EXAMPLES.md            # Usage examples
```

## Build Instructions

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    linux-headers-$(uname -r) \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    clang \
    llvm \
    python3-pip

# Fedora/RHEL
sudo dnf install -y \
    gcc \
    make \
    kernel-devel \
    libbpf-devel \
    elfutils-libelf-devel \
    zlib-devel \
    clang \
    llvm

# For eBPF development
sudo pip3 install bcc
```

### Building the Library

```bash
# Clone the repository
git clone https://github.com/your-org/upcl.git
cd upcl

# Build everything
make all

# Build only the library
make lib

# Build examples
make examples

# Build kernel module (requires root)
sudo make kmod

# Install system-wide
sudo make install

# Run tests
make test
```

### Build Options

```bash
# Debug build
make DEBUG=1

# Specific architecture
make ARCH=arm64

# Custom installation prefix
make PREFIX=/usr/local install

# Build with specific compiler
make CC=clang

# Parallel build
make -j$(nproc)
```

## Quick Start

### 1. Basic CPU Profiling

```c
#include <upcl.h>

int main() {
    // Initialize
    upcl_init();
    
    // Configure
    upcl_config_t config = {
        .methods = UPCL_METHOD_PERF,
        .data_types = UPCL_DATA_CPU_CYCLES | UPCL_DATA_INSTRUCTIONS,
        .sample_freq = 1000,
        .output_format = UPCL_FORMAT_JSON,
        .output_path = "profile.json"
    };
    
    // Create and start session
    upcl_session_t session = upcl_session_create(&config);
    upcl_session_start(session);
    
    // Your application code here
    
    // Stop and cleanup
    upcl_session_stop(session);
    upcl_session_destroy(session);
    return 0;
}
```

### 2. Compile and Run

```bash
# Compile your application
gcc -o myapp myapp.c -lupcl

# Run with profiling
./myapp

# View results
cat profile.json | python -m json.tool
```

### 3. Using the Kernel Module

```bash
# Load the module
sudo insmod kernel/upcl.ko

# Check if loaded
lsmod | grep upcl

# Use via device interface
sudo ./examples/example_kernel
```

### 4. eBPF Tracing

```bash
# Run eBPF example (requires root)
sudo ./examples/example_ebpf

# Trace specific functions
sudo ./tools/upcl-record -e bpf -f do_sys_open -o trace.bin
```

## Configuration Examples

### High-Frequency Sampling
```c
config.sample_freq = 10000;  // 10 kHz
config.mmap_pages = 256;     // Larger buffers
```

### Intel PEBS
```c
config.platform.intel.precise_ip = 2;
config.platform.intel.pebs = 1;
```

### AMD IBS
```c
config.platform.amd.ibs_fetch = 1;
config.platform.amd.ibs_op = 1;
```

### Custom PMU Events
```c
config.custom_events[0].type = PERF_TYPE_RAW;
config.custom_events[0].config = 0x412e;  // L3 miss
config.nr_custom_events = 1;
```

## Troubleshooting

### Permission Errors
```bash
# Check perf_event_paranoid
cat /proc/sys/kernel/perf_event_paranoid

# Allow non-root access (temporary)
sudo sysctl kernel.perf_event_paranoid=1

# Or run with CAP_SYS_ADMIN
sudo setcap cap_sys_admin+ep ./myapp
```

### Missing eBPF Support
```bash
# Check kernel config
zgrep CONFIG_BPF /proc/config.gz

# Required configs:
# CONFIG_BPF=y
# CONFIG_BPF_SYSCALL=y
# CONFIG_BPF_EVENTS=y
```

### Build Errors
```bash
# Missing headers
sudo apt-get install linux-headers-$(uname -r)

# Missing libbpf
git clone https://github.com/libbpf/libbpf
cd libbpf/src
make && sudo make install
```

## Performance Considerations

- **Sampling Rate**: Higher rates provide more detail but increase overhead
- **Buffer Size**: Larger buffers reduce data loss but use more memory
- **CPU Affinity**: Pin collection to specific CPUs to reduce interference
- **Filtering**: Use PID/CPU filters to reduce data volume

## License

GPL v2 - Compatible with Linux kernel modules

## Contributing

Contributions welcome! Please ensure:
- Code follows kernel coding style
- Platform-specific code is properly isolated
- Performance overhead is documented
- Tests pass on Intel, AMD, and ARM platforms
