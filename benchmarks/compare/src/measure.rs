use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

struct CountingAllocator;
static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn record_allocation(pointer: *mut u8, size: usize) {
    if !pointer.is_null() && COUNTING.load(Ordering::Relaxed) {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(size as u64, Ordering::Relaxed);
    }
}

// Instrumentation wraps the system allocator; it does not change allocation
// sizes, reuse memory, or hide deallocation work. Counters are enabled only in a
// separate allocation pass, so atomic increments do not bias the timing pass.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        record_allocation(pointer, layout.size());
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        record_allocation(pointer, layout.size());
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, new_size) };
        record_allocation(result, new_size);
        result
    }
}

fn allocations(operation: &mut impl FnMut()) -> (u64, u64) {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    operation();
    COUNTING.store(false, Ordering::Relaxed);
    (
        ALLOCATIONS.load(Ordering::Relaxed),
        ALLOCATED_BYTES.load(Ordering::Relaxed),
    )
}

pub fn allocator_self_check() {
    let before = thread_cpu_ns();
    assert!(
        thread_cpu_ns() >= before,
        "thread CPU clock must be available and monotonic"
    );
    let (count, bytes) = allocations(&mut || {
        let value = black_box(vec![42u8; 1024]);
        black_box(value.as_slice());
        drop(value);
    });
    assert_eq!(
        count, 1,
        "allocator instrumentation must observe one Vec allocation"
    );
    assert_eq!(
        bytes, 1024,
        "allocator instrumentation must observe the requested size"
    );
    assert_eq!(
        allocations(&mut || {
            black_box(42u64);
        }),
        (0, 0)
    );
}

fn thread_cpu_ns() -> u64 {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut timestamp) };
    assert_eq!(result, 0, "CLOCK_THREAD_CPUTIME_ID is required");
    timestamp.tv_sec as u64 * 1_000_000_000 + timestamp.tv_nsec as u64
}

pub fn pin_to_cpu(requested: Option<usize>) -> io::Result<usize> {
    let mut allowed: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::cpu_set_t>();
    if unsafe { libc::sched_getaffinity(0, size, &mut allowed) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let chosen = requested
        .or_else(|| {
            (0..libc::CPU_SETSIZE as usize).find(|cpu| unsafe { libc::CPU_ISSET(*cpu, &allowed) })
        })
        .ok_or_else(|| io::Error::other("no permitted CPU"))?;
    if chosen >= libc::CPU_SETSIZE as usize || !unsafe { libc::CPU_ISSET(chosen, &allowed) } {
        return Err(io::Error::other(
            "requested CPU is outside the allowed affinity set",
        ));
    }
    let mut selected: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::CPU_SET(chosen, &mut selected) };
    if unsafe { libc::sched_setaffinity(0, size, &selected) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(chosen)
}

#[derive(Clone, Copy)]
pub struct Sample {
    pub round: usize,
    pub position: usize,
    pub variant: &'static str,
    pub wall_ns: u64,
    pub cpu_ns: u64,
    pub allocations: u64,
    pub allocated_bytes: u64,
}

fn sample(
    round: usize,
    position: usize,
    variant: &'static str,
    operation: &mut impl FnMut(),
) -> Sample {
    let cpu_start = thread_cpu_ns();
    let wall_start = Instant::now();
    operation();
    let wall_ns = wall_start.elapsed().as_nanos() as u64;
    let cpu_ns = thread_cpu_ns() - cpu_start;
    let (allocations, allocated_bytes) = allocations(operation);
    Sample {
        round,
        position,
        variant,
        wall_ns,
        cpu_ns,
        allocations,
        allocated_bytes,
    }
}

pub struct Case {
    pub name: &'static str,
    pub comparability: &'static str,
    pub samples: Vec<Sample>,
}

pub struct Runner {
    pub samples: usize,
    pub warmup: usize,
    pub check_only: bool,
    pub cases: Vec<Case>,
}

impl Runner {
    pub fn pair(
        &mut self,
        name: &'static str,
        comparability: &'static str,
        mut baseline: impl FnMut(),
        mut candidate: impl FnMut(),
    ) {
        if self.check_only {
            baseline();
            candidate();
            return;
        }
        for round in 0..self.warmup {
            if round % 2 == 0 {
                baseline();
                candidate();
            } else {
                candidate();
                baseline();
            }
        }
        let mut samples = Vec::with_capacity(self.samples * 2);
        for round in 0..self.samples {
            if round % 2 == 0 {
                samples.push(sample(round, 0, "baseline", &mut baseline));
                samples.push(sample(round, 1, "candidate", &mut candidate));
            } else {
                samples.push(sample(round, 0, "candidate", &mut candidate));
                samples.push(sample(round, 1, "baseline", &mut baseline));
            }
        }
        self.cases.push(Case {
            name,
            comparability,
            samples,
        });
        eprintln!("measured {name}: {} paired samples", self.samples);
    }

    pub fn candidate_only(&mut self, name: &'static str, mut operation: impl FnMut()) {
        if self.check_only {
            operation();
            return;
        }
        for _ in 0..self.warmup {
            operation();
        }
        let mut samples = Vec::with_capacity(self.samples);
        for round in 0..self.samples {
            samples.push(sample(round, 0, "candidate", &mut operation));
        }
        self.cases.push(Case {
            name,
            comparability: "candidate_only_no_equivalent_baseline",
            samples,
        });
        eprintln!("measured {name}: {} candidate samples", self.samples);
    }

    pub fn write(&self, directory: &Path) -> io::Result<()> {
        let mut raw =
            std::io::BufWriter::new(std::fs::File::create(directory.join("samples.csv"))?);
        writeln!(
            raw,
            "case,comparability,round,position,variant,wall_ns,thread_cpu_ns,allocations,allocated_bytes"
        )?;
        let mut summary =
            std::io::BufWriter::new(std::fs::File::create(directory.join("summary.csv"))?);
        writeln!(
            summary,
            "case,comparability,variant,n,wall_p50_ns,wall_p95_ns,wall_p99_ns,cpu_p50_ns,cpu_p95_ns,cpu_p99_ns,allocations_p50,allocations_mean,allocated_bytes_p50,allocated_bytes_mean"
        )?;
        for case in &self.cases {
            for sample in &case.samples {
                writeln!(
                    raw,
                    "{},{},{},{},{},{},{},{},{}",
                    case.name,
                    case.comparability,
                    sample.round,
                    sample.position,
                    sample.variant,
                    sample.wall_ns,
                    sample.cpu_ns,
                    sample.allocations,
                    sample.allocated_bytes
                )?;
            }
            for variant in ["baseline", "candidate"] {
                let matching: Vec<_> = case
                    .samples
                    .iter()
                    .filter(|sample| sample.variant == variant)
                    .collect();
                if matching.is_empty() {
                    continue;
                }
                let wall = sorted(matching.iter().map(|sample| sample.wall_ns));
                let cpu = sorted(matching.iter().map(|sample| sample.cpu_ns));
                let counts = sorted(matching.iter().map(|sample| sample.allocations));
                let bytes = sorted(matching.iter().map(|sample| sample.allocated_bytes));
                writeln!(
                    summary,
                    "{},{},{},{},{},{},{},{},{},{},{},{:.3},{},{:.3}",
                    case.name,
                    case.comparability,
                    variant,
                    matching.len(),
                    percentile(&wall, 50),
                    percentile(&wall, 95),
                    percentile(&wall, 99),
                    percentile(&cpu, 50),
                    percentile(&cpu, 95),
                    percentile(&cpu, 99),
                    percentile(&counts, 50),
                    mean(&counts),
                    percentile(&bytes, 50),
                    mean(&bytes)
                )?;
            }
        }
        raw.flush()?;
        summary.flush()
    }
}

fn sorted(values: impl Iterator<Item = u64>) -> Vec<u64> {
    let mut values: Vec<_> = values.collect();
    values.sort_unstable();
    values
}

fn percentile(values: &[u64], percentage: usize) -> u64 {
    values[(values.len() * percentage).div_ceil(100) - 1]
}

fn mean(values: &[u64]) -> f64 {
    values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64
}
