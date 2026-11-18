use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::hint::black_box;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

struct Allocator;
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
static COUNTING: AtomicBool = AtomicBool::new(false);
static TRACING: AtomicBool = AtomicBool::new(false);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
const STACK_DEPTH: usize = 32;
const TRACE_CAPACITY: usize = 8192;
#[derive(Clone, Copy)]
struct Trace {
    bytes: usize,
    depth: usize,
    frames: [usize; STACK_DEPTH],
}
struct Traces(UnsafeCell<[Trace; TRACE_CAPACITY]>);
// The harness runs one thread. COUNTING is disabled around unwinding, and
// traces are read only after recording has stopped.
unsafe impl Sync for Traces {}
static TRACES: Traces = Traces(UnsafeCell::new(
    [Trace {
        bytes: 0,
        depth: 0,
        frames: [0; STACK_DEPTH],
    }; TRACE_CAPACITY],
));
unsafe extern "C" {
    fn backtrace(buffer: *mut *mut libc::c_void, size: libc::c_int) -> libc::c_int;
}

fn record(pointer: *mut u8, size: usize) {
    if pointer.is_null() || !COUNTING.load(Ordering::Relaxed) {
        return;
    }
    let index = CALLS.fetch_add(1, Ordering::Relaxed);
    BYTES.fetch_add(size, Ordering::Relaxed);
    if TRACING.load(Ordering::Relaxed) && index < TRACE_CAPACITY {
        COUNTING.store(false, Ordering::Relaxed);
        let trace = unsafe { &mut (*TRACES.0.get())[index] };
        trace.bytes = size;
        trace.depth =
            unsafe { backtrace(trace.frames.as_mut_ptr().cast(), STACK_DEPTH as _) } as usize;
        COUNTING.store(true, Ordering::Relaxed);
    }
}
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        record(p, layout.size());
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        record(p, layout.size());
        p
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(p, layout, size) };
        record(p, size);
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) }
    }
}
fn start(trace: bool) {
    CALLS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    TRACING.store(trace, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
}
fn stop() -> (usize, usize) {
    COUNTING.store(false, Ordering::Relaxed);
    (CALLS.load(Ordering::Relaxed), BYTES.load(Ordering::Relaxed))
}
fn cpu_ns() -> u64 {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) },
        0
    );
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}
pub fn pin(requested: Option<usize>) -> io::Result<usize> {
    let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::cpu_set_t>();
    if unsafe { libc::sched_getaffinity(0, size, &mut mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let cpu = requested
        .or_else(|| {
            (0..libc::CPU_SETSIZE as usize).find(|cpu| unsafe { libc::CPU_ISSET(*cpu, &mask) })
        })
        .ok_or_else(|| io::Error::other("no permitted CPU"))?;
    if cpu >= libc::CPU_SETSIZE as usize || !unsafe { libc::CPU_ISSET(cpu, &mask) } {
        return Err(io::Error::other("CPU outside allowed affinity"));
    }
    unsafe {
        libc::CPU_ZERO(&mut mask);
        libc::CPU_SET(cpu, &mut mask);
    }
    if unsafe { libc::sched_setaffinity(0, size, &mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cpu)
}
pub fn self_check() {
    let mut frames = [0usize; STACK_DEPTH];
    unsafe {
        backtrace(frames.as_mut_ptr().cast(), STACK_DEPTH as _);
    }
    start(false);
    drop(black_box(vec![0u8; 1024]));
    assert_eq!(stop(), (1, 1024));
    start(false);
    black_box(42u64);
    assert_eq!(stop(), (0, 0));
}
pub struct Sample {
    pub case: &'static str,
    pub observation: usize,
    pub wall_ns: u64,
    pub cpu_ns: u64,
    pub calls: usize,
    pub bytes: usize,
}
pub struct Runner {
    pub samples: usize,
    pub warmup: usize,
    pub selected: Option<String>,
    pub profile: bool,
    pub profile_iterations: usize,
    pub output: std::path::PathBuf,
    pub results: Vec<Sample>,
    pub executed: usize,
}
impl Runner {
    pub fn run<T, R>(
        &mut self,
        name: &'static str,
        mut setup: impl FnMut() -> T,
        mut operation: impl FnMut(T) -> R,
    ) -> io::Result<()> {
        if self.selected.as_ref().is_some_and(|s| s != name) {
            return Ok(());
        }
        self.executed += 1;
        // Setup is outside both measured passes, including ownership preparation
        // for finish(). Result destruction belongs to the measured operation.
        for _ in 0..self.warmup {
            drop(black_box(operation(setup())));
        }
        if self.profile {
            let input = setup();
            start(true);
            drop(black_box(operation(input)));
            let (calls, bytes) = stop();
            write_traces(
                &self.output.join(format!("{name}-allocations.csv")),
                calls,
                bytes,
            )?;
            for _ in 1..self.profile_iterations {
                drop(black_box(operation(setup())));
            }
            return Ok(());
        }
        self.results.reserve(self.samples);
        for observation in 0..self.samples {
            let input = setup();
            let start_cpu = cpu_ns();
            let start_wall = Instant::now();
            drop(black_box(operation(input)));
            let wall_ns = start_wall.elapsed().as_nanos() as u64;
            let cpu_ns = cpu_ns() - start_cpu;
            let input = setup();
            start(false);
            drop(black_box(operation(input)));
            let (calls, bytes) = stop();
            self.results.push(Sample {
                case: name,
                observation,
                wall_ns,
                cpu_ns,
                calls,
                bytes,
            });
        }
        eprintln!("{name}: {} observations", self.samples);
        Ok(())
    }
    pub fn write(&self) -> io::Result<()> {
        let mut file = io::BufWriter::new(std::fs::File::create(self.output.join("samples.csv"))?);
        writeln!(
            file,
            "case,observation,wall_ns,thread_cpu_ns,allocations,requested_bytes"
        )?;
        for s in &self.results {
            writeln!(
                file,
                "{},{},{},{},{},{}",
                s.case, s.observation, s.wall_ns, s.cpu_ns, s.calls, s.bytes
            )?;
        }
        file.flush()
    }
}
fn write_traces(path: &Path, calls: usize, bytes: usize) -> io::Result<()> {
    assert!(
        calls <= TRACE_CAPACITY,
        "allocation trace capacity exceeded"
    );
    let mut file = io::BufWriter::new(std::fs::File::create(path)?);
    writeln!(
        file,
        "# calls={calls} requested_bytes={bytes}; one successful operation; allocations only; no timing"
    )?;
    writeln!(file, "allocation,requested_bytes,frame,elf_offset,object")?;
    for index in 0..calls {
        let trace = unsafe { &(*TRACES.0.get())[index] };
        for (frame, address) in trace.frames[..trace.depth].iter().enumerate() {
            let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
            let found = unsafe { libc::dladdr(*address as *const _, &mut info) };
            if found != 0 {
                let object = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }.to_string_lossy();
                let offset = address - info.dli_fbase as usize;
                writeln!(file, "{index},{},{frame},{offset:x},{object}", trace.bytes)?;
            }
        }
    }
    file.flush()
}
