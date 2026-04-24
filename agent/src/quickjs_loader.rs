//! QuickJS loader module for the agent
//!
//! This module provides JavaScript loading and execution capabilities
//! using the quickjs-hook crate.

#![cfg(feature = "quickjs")]

use crate::vma_name::set_anon_vma_name_raw;
use libc::{munmap, sysconf, MAP_FAILED, _SC_PAGESIZE};

use quickjs_hook::{
    cleanup_engine, cleanup_wxshadow_patches, complete_script, cut_art_controller_routing_hooks,
    cut_art_controller_walkstack_guards, cut_java_hooks, cut_native_hooks, drain_thunk_in_flight,
    free_art_controller_state, free_java_hooks, free_native_hooks, get_or_init_engine, init_hook_engine, load_script,
    load_script_with_filename, set_console_callback, set_qbdi_helper_blob, set_qbdi_output_dir,
};
#[cfg(feature = "qbdi")]
use quickjs_hook::{preload_qbdi_helper, shutdown_qbdi_helper};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use crate::communication::{log_msg, write_stream};

static ENGINE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static HOOK_EXEC_VMA_NAME: &[u8] = b"wwb_hook_exec\0";

/// 从 /proc/self/maps 找 libart.so 的 r-xp 基址（用作 mmap hint）
fn find_libart_base() -> Option<usize> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        if line.contains("libart.so") && line.contains("r-xp") {
            let addr = line.split('-').next()?;
            return usize::from_str_radix(addr, 16).ok();
        }
    }
    None
}

/// Executable memory for hooks
static EXEC_MEM: OnceLock<ExecMemory> = OnceLock::new();

/// Executable memory region wrapper
struct ExecMemory {
    ptr: *mut u8,
    size: usize,
}

impl ExecMemory {
    /// 调用 C 侧 hook_mmap_near 扫描 maps 空隙分配 nearby RWX 内存。
    /// hint=0 时退化为普通 mmap。
    fn new_near(size: usize, hint: usize) -> Option<Self> {
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        let alloc_size = ((size + page_size - 1) / page_size) * page_size;

        extern "C" {
            fn hook_mmap_near(target: *mut std::ffi::c_void, alloc_size: usize) -> *mut std::ffi::c_void;
        }

        let ptr = unsafe { hook_mmap_near(hint as *mut std::ffi::c_void, alloc_size) };

        if ptr == MAP_FAILED as *mut std::ffi::c_void {
            return None;
        }

        match set_anon_vma_name_raw(ptr as *mut u8, alloc_size, HOOK_EXEC_VMA_NAME) {
            Ok(()) => {}
            Err(_) => {}
        }

        Some(ExecMemory {
            ptr: ptr as *mut u8,
            size: alloc_size,
        })
    }

    fn new(size: usize) -> Option<Self> {
        Self::new_near(size, 0)
    }

    fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    fn size(&self) -> usize {
        self.size
    }
}

impl Drop for ExecMemory {
    fn drop(&mut self) {
        unsafe {
            munmap(self.ptr as *mut _, self.size);
        }
    }
}

// Safety: ExecMemory is only accessed from the JS thread
unsafe impl Send for ExecMemory {}
unsafe impl Sync for ExecMemory {}

/// Initialize the QuickJS engine and hook system
pub fn init() -> Result<(), String> {
    if ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("JS 引擎已初始化".to_string());
    }

    // Allocate executable memory for hooks (64KB), near libart.so for ADRP range
    let libart_hint = find_libart_base().unwrap_or(0);
    let exec_mem = EXEC_MEM
        .get_or_init(|| ExecMemory::new_near(64 * 1024, libart_hint).expect("Failed to allocate executable memory"));

    // Initialize hook engine
    init_hook_engine(exec_mem.as_ptr(), exec_mem.size())?;

    // 注册 recomp handlers
    quickjs_hook::recomp::set_handler(|addr| crate::recompiler::ensure_and_translate(addr));
    quickjs_hook::recomp::set_alloc_slot_handler(|addr| crate::recompiler::alloc_trampoline_slot(addr));
    quickjs_hook::recomp::set_fixup_handler(|trampoline, addr| {
        crate::recompiler::fixup_slot_trampoline(trampoline, addr)
    });
    quickjs_hook::recomp::set_commit_handler(|addr| crate::recompiler::commit_slot_patch(addr));
    quickjs_hook::recomp::set_revert_handler(|addr| crate::recompiler::revert_slot_patch(addr));
    quickjs_hook::recomp::set_install_patch_handler(|addr, bytes| crate::recompiler::install_patch(addr, bytes));
    quickjs_hook::recomp::set_try_revert_handler(|addr| crate::recompiler::try_revert_slot_patch(addr));

    if let Some(output_path) = crate::OUTPUT_PATH.get() {
        set_qbdi_output_dir(output_path.clone());
    }

    // 先设置 console callback，确保引擎初始化期间的日志（如 [jniIds]）能通过 socket 输出
    set_console_callback(|msg| {
        write_stream(format!("[JS] {}", msg).as_bytes());
    });

    // 初始化 JS 引擎（complete_script 依赖它）
    get_or_init_engine()?;

    #[cfg(feature = "qbdi")]
    if let Err(err) = preload_qbdi_helper() {
        if err != "qbdi helper blob not configured" {
            write_stream(format!("[qbdi] preload on jsinit failed: {}", err).as_bytes());
        }
    }

    ENGINE_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}

pub fn install_qbdi_helper(blob: Vec<u8>) {
    set_qbdi_helper_blob(blob);
    #[cfg(feature = "qbdi")]
    if let Err(err) = preload_qbdi_helper() {
        write_stream(format!("[qbdi] preload on helper install failed: {}", err).as_bytes());
    }
}

/// Load and execute a JavaScript script
pub fn execute_script(script: &str) -> Result<String, String> {
    if !ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("JS 引擎未初始化，请先执行 jsinit".to_string());
    }

    load_script(script)
}

/// Load + execute 指定源文件名的脚本（错误信息会显示 `filename:line:col`）
pub fn execute_script_with_filename(script: &str, filename: &str) -> Result<String, String> {
    if !ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("JS 引擎未初始化，请先执行 jsinit".to_string());
    }

    load_script_with_filename(script, filename)
}

/// Get tab-completion candidates for the given prefix from the live JS engine.
pub fn complete(prefix: &str) -> String {
    if !ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return String::new();
    }
    let candidates = complete_script(prefix);
    candidates.join("\t")
}

/// 检查 JS 引擎是否已初始化
pub fn is_initialized() -> bool {
    ENGINE_INITIALIZED.load(Ordering::SeqCst)
}

/// Cleanup QuickJS resources — 4 阶段编排
///
/// Phase 1: **切断所有 hook 入口** (Java + Native + OAT inline)。之后 g_thunk_in_flight 只减不增。
/// Phase 2: **drain g_thunk_in_flight → 0**。归零表示无线程在 thunk 或 callee 中。
/// Phase 3: **释放资源** (ArtMethod 堆、JNI global ref、JS callback、JS runtime、art_controller state)。
/// Phase 4: **hook_engine cleanup + munmap pool/recomp 页**。
pub fn cleanup() {
    use std::time::Instant;
    let t0 = Instant::now();
    let mut t = t0;
    let mut stage = |label: &str, prev: &mut Instant| {
        let now = Instant::now();
        let delta = now.duration_since(*prev).as_millis();
        let total = now.duration_since(t0).as_millis();
        log_msg(format!("[quickjs] {} (+{}ms, total {}ms)\n", label, delta, total));
        *prev = now;
    };

    stage("cleanup start", &mut t);
    ENGINE_INITIALIZED.store(false, Ordering::SeqCst);

    // ============================================================
    // Phase 1: 切断所有 "入口 / 路由" hook，阻止新 thunk 进入。
    //   - Java per-method inline patch (Layer 3)
    //   - Native hook (export 入口)
    //   - art_controller 路由: Layer1 (shared stub) / Layer2 (DoCall) / GC 同步 / Fixup
    //
    //   **刻意保留** walkstack 防护 (OAT header hook / PrettyMethod / 内联 OAT patch) ——
    //   它们只影响 ART 看到 thunk frame 时会不会 abort，与路由无关。
    //   必须等 drain=0 (栈上无任何 thunk PC) 后才能拆。
    // ============================================================
    cut_java_hooks();
    stage("phase1 cut_java_hooks", &mut t);
    cut_native_hooks();
    stage("phase1 cut_native_hooks", &mut t);
    cut_art_controller_routing_hooks();
    stage("phase1 cut_art_controller_routing", &mut t);

    // ============================================================
    // Phase 2: drain g_thunk_in_flight → 0
    //   归零 → 无 in-flight thunk → 栈上不可能再有 thunk LR
    //   → OAT bypass 可以安全卸载
    //   → pool 可以安全 munmap
    // ============================================================
    // drain_thunk_in_flight 现在无限等待直到归零 (never returns false),
    // 保证 Phase 3/4 安全执行, 不再走 leak 分支。若线程真卡死, 外层会一直等。
    let _drained = drain_thunk_in_flight();
    stage("phase2 drain_thunk_in_flight", &mut t);

    // ============================================================
    // Phase 3: 释放资源 (drain 归零后才安全拆 OAT bypass)
    //   OAT bypass 拆和 pool munmap 是原子事件 —— 一旦拆了 bypass, pool 必须立刻 munmap
    //   (否则残留 PC 访问 pool → no bypass 保护 → WalkStack 炸)
    // ============================================================
    cut_art_controller_walkstack_guards();
    stage("phase3 cut_art_controller_walkstack_guards", &mut t);
    free_art_controller_state();
    stage("phase3 free_art_controller_state", &mut t);
    free_java_hooks();
    stage("phase3 free_java_hooks", &mut t);
    free_native_hooks();
    stage("phase3 free_native_hooks", &mut t);
    #[cfg(feature = "qbdi")]
    {
        shutdown_qbdi_helper();
        stage("phase3 shutdown_qbdi_helper", &mut t);
    }
    cleanup_engine();
    stage("phase3 cleanup_engine", &mut t);

    // ============================================================
    // Phase 4: 同步释放 pool + recomp (drain 已归零, 确认无 in-flight)
    // ============================================================
    cleanup_wxshadow_patches();
    stage("phase4 cleanup_wxshadow_patches", &mut t);
    crate::recompiler::release_all();
    stage("phase4 release_all_recomp", &mut t);
    let (recomp_ok, recomp_fail, recomp_bytes) = unsafe { crate::recompiler::munmap_retained_ranges() };
    if recomp_ok + recomp_fail > 0 {
        log_msg(format!(
            "[quickjs] munmap recomp: ok={} fail={} bytes={}\n",
            recomp_ok, recomp_fail, recomp_bytes
        ));
    }
    unsafe {
        quickjs_hook::ffi::hook::hook_engine_munmap_pools_direct();
    }
    stage("phase4 munmap_pools_direct", &mut t);

    log_msg(format!(
        "[quickjs] cleanup done (total {}ms)\n",
        t0.elapsed().as_millis()
    ));
}

// 注：旧的 munmap_retained_ranges_final (快照 snap → munmap) 已废弃，由
// hook_engine_munmap_pools_direct (C 侧直读 g_engine.pools[] 同步 munmap) 取代。
// drain 超时路径不释放 pool/recomp/walkstack guards，泄漏到进程退出。

/// **软清理**：完整 unhook + drain=0 + 销毁 runtime，保留 hook 基础设施和 RWX 内存。
///
/// `%reload` 使用。与 full `cleanup()` 相同的 hook 释放路径（drain=0 原子不变量保持），
/// 但刻意保留 art_controller / pool / recomp 页 / wxshadow —— 这些内存可能仍被 ART
/// 内部的 ArtMethod 拷贝 / class copy / OAT 缓存引用。full cleanup 的 munmap 只在
/// agent 退出（地址永不复用）时安全；同进程 reload 必须保留。
///
/// 做：
/// - Phase 1: `cut_java_hooks` + `cut_native_hooks`（per-hook wxshadow/recomp-B 反转在这里）
/// - Phase 2: `drain_thunk_in_flight` → 0
/// - Phase 3: `free_java_hooks` + `free_native_hooks` + `cleanup_engine`
///
/// 保留：art_controller routing + walkstack guards + hook pools + recomp 页 + wxshadow。
///
/// drain 超时：拒绝 free，返回 Err，调用方中止 reload。
pub fn cleanup_soft() -> Result<(), String> {
    use std::time::Instant;

    if !ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("JS 引擎未初始化".to_string());
    }

    let t0 = Instant::now();
    let mut t = t0;
    let mut stage = |label: &str, prev: &mut Instant| {
        let now = Instant::now();
        let delta = now.duration_since(*prev).as_millis();
        let total = now.duration_since(t0).as_millis();
        log_msg(format!("[quickjs-soft] {} (+{}ms, total {}ms)\n", label, delta, total));
        *prev = now;
    };

    stage("soft cleanup start", &mut t);

    // Phase 1: 切 JS 侧入口（保留 art_controller routing / walkstack guards）
    cut_java_hooks();
    stage("phase1 cut_java_hooks", &mut t);
    cut_native_hooks();
    stage("phase1 cut_native_hooks", &mut t);

    // Phase 2: drain thunk —— 必须归零才能安全 free callback JSValue
    let drained = drain_thunk_in_flight();
    stage("phase2 drain_thunk_in_flight", &mut t);

    if !drained {
        log_msg(format!(
            "[quickjs-soft] drain 未归零：保留 hook 资源 (leak 到进程退出). \
             拒绝降级 (会让醒来的线程 UAF JS callback). total {}ms\n",
            t0.elapsed().as_millis()
        ));
        return Err("drain timeout，软清理已放弃".to_string());
    }

    // Phase 3: 完整 free JS hook 资源 + 销毁 runtime
    free_java_hooks();
    stage("phase3 free_java_hooks", &mut t);
    free_native_hooks();
    stage("phase3 free_native_hooks", &mut t);
    ENGINE_INITIALIZED.store(false, Ordering::SeqCst);
    cleanup_engine();
    stage("phase3 cleanup_engine", &mut t);

    log_msg(format!(
        "[quickjs-soft] soft cleanup done (total {}ms) — art_controller + pool + recomp 保留\n",
        t0.elapsed().as_millis()
    ));
    Ok(())
}
