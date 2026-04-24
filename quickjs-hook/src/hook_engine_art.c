/*
 * hook_engine_art.c - ART method router: table, thunk generation, router hooks
 *
 * Contains: ART router lookup table management, debug functions,
 * FP instruction helpers, generate_art_router_thunk, resolve_art_trampoline,
 * hook_install_art_router, hook_create_art_router_stub.
 */

#include "hook_engine_internal.h"

/* --- ART router lookup table (inline scan from generated thunk) --- */

ArtRouterEntry g_art_router_table[ART_ROUTER_TABLE_MAX];

/* Debug: last X0 seen in not_found path + miss counter */
volatile uint64_t g_art_router_last_x0 = 0;
volatile uint64_t g_art_router_miss_count = 0;
/* Debug: hit counter for found path */
volatile uint64_t g_art_router_hit_count = 0;
volatile uint64_t g_art_router_last_hit_x0 = 0;
volatile uint64_t g_art_router_quick_hit_count = 0;
volatile uint64_t g_art_router_quick_pass_count = 0;
volatile uint64_t g_art_router_quick_callback_count = 0;
volatile uint64_t g_art_router_quick_skip_count = 0;
volatile uint64_t g_art_router_replacement_hit_count = 0;
volatile uint64_t g_art_router_do_call_table_hit_count = 0;
volatile uint64_t g_art_router_last_do_call_x0 = 0;

/* Fast $orig bypass state */
OrigBypassState g_orig_bypass[ORIG_BYPASS_SLOTS] = {{0}};
volatile uint64_t g_orig_bypass_active = 0;
volatile uint64_t g_orig_bypass_hit = 0;

/* ============================================================================
 * ART router table management
 * ============================================================================ */

int hook_art_router_table_add(uint64_t original, uint64_t replacement) {
    hook_log("[art_router] table_add: original=%llx, replacement=%llx",
             (unsigned long long)original, (unsigned long long)replacement);
    /* Find first empty slot (original == 0 is sentinel) */
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == original) {
            /* Already exists — update replacement */
            g_art_router_table[i].replacement = replacement;
            g_art_router_table[i].mode = 0;
            g_art_router_table[i].quick_callback = NULL;
            g_art_router_table[i].quick_user_data = NULL;
            return 0;
        }
        if (g_art_router_table[i].original == 0) {
            g_art_router_table[i].original = original;
            g_art_router_table[i].replacement = replacement;
            g_art_router_table[i].mode = 0;
            g_art_router_table[i].quick_callback = NULL;
            g_art_router_table[i].quick_user_data = NULL;
            return 0;
        }
    }
    hook_log("[art_router] table full (max %d)", ART_ROUTER_TABLE_MAX);
    return -1;
}

int hook_art_router_table_add_quick(uint64_t original, uint64_t replacement,
                                    HookCallback callback, void* user_data) {
    hook_log("[art_router] table_add_quick: original=%llx, replacement=%llx, callback=%p",
             (unsigned long long)original, (unsigned long long)replacement, (void*)callback);
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == original) {
            g_art_router_table[i].replacement = replacement;
            g_art_router_table[i].mode = 1;
            g_art_router_table[i].quick_callback = callback;
            g_art_router_table[i].quick_user_data = user_data;
            return 0;
        }
        if (g_art_router_table[i].original == 0) {
            g_art_router_table[i].original = original;
            g_art_router_table[i].replacement = replacement;
            g_art_router_table[i].mode = 1;
            g_art_router_table[i].quick_callback = callback;
            g_art_router_table[i].quick_user_data = user_data;
            return 0;
        }
    }
    hook_log("[art_router] table full (max %d)", ART_ROUTER_TABLE_MAX);
    return -1;
}

void hook_art_router_table_set_mode(uint64_t original, uint64_t mode) {
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) break;
        if (g_art_router_table[i].original == original) {
            g_art_router_table[i].mode = mode;
            return;
        }
    }
}

int hook_art_router_table_remove(uint64_t original) {
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0)
            break; /* hit sentinel — not found */
        if (g_art_router_table[i].original == original) {
            /* Shift remaining entries down to keep table compact */
            int j = i;
            while (j + 1 < ART_ROUTER_TABLE_MAX && g_art_router_table[j + 1].original != 0) {
                g_art_router_table[j] = g_art_router_table[j + 1];
                j++;
            }
            g_art_router_table[j].original = 0;
            g_art_router_table[j].replacement = 0;
            g_art_router_table[j].mode = 0;
            g_art_router_table[j].quick_callback = NULL;
            g_art_router_table[j].quick_user_data = NULL;
            return 0;
        }
    }
    return -1;
}

void hook_art_router_table_clear(void) {
    memset(g_art_router_table, 0, sizeof(g_art_router_table));
}

/* 反查: 给定 replacement，返回对应的 original（callOriginal bypass 用） */
uint64_t hook_art_router_table_lookup_original(uint64_t replacement) {
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) break;
        if (g_art_router_table[i].replacement == replacement)
            return g_art_router_table[i].original;
    }
    return 0;
}

int hook_art_router_record_do_call(uint64_t method) {
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) break;
        if (g_art_router_table[i].original == method) {
            __atomic_add_fetch(&g_art_router_do_call_table_hit_count, 1, __ATOMIC_RELAXED);
            __atomic_store_n(&g_art_router_last_do_call_x0, method, __ATOMIC_RELAXED);
            return g_art_router_table[i].mode ? 1 : 2;
        }
    }
    return 0;
}

void hook_art_router_table_dump(void) {
    hook_log("[art_router] table dump (addr=%p):", (void*)g_art_router_table);
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) {
            hook_log("[art_router]   [%d] <end> (total %d entries)", i, i);
            return;
        }
        hook_log("[art_router]   [%d] original=%llx -> replacement=%llx mode=%llx",
                 i,
                 (unsigned long long)g_art_router_table[i].original,
                 (unsigned long long)g_art_router_table[i].replacement,
                 (unsigned long long)g_art_router_table[i].mode);
    }
    hook_log("[art_router]   table full (%d entries)", ART_ROUTER_TABLE_MAX);
}

int hook_art_router_debug_scan(uint64_t x0) {
    hook_log("[art_router] debug_scan: searching for x0=%llx", (unsigned long long)x0);
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) {
            hook_log("[art_router] debug_scan: NOT FOUND after %d entries", i);
            return 0;
        }
        if (g_art_router_table[i].original == x0) {
            hook_log("[art_router] debug_scan: FOUND at [%d] -> replacement=%llx mode=%llx",
                     i, (unsigned long long)g_art_router_table[i].replacement,
                     (unsigned long long)g_art_router_table[i].mode);
            return 1;
        }
    }
    hook_log("[art_router] debug_scan: NOT FOUND (table full)");
    return 0;
}

void hook_dump_code(void* addr, size_t size) {
    if (!addr || size == 0) return;
    hook_log("[dump_code] %p (%zu bytes):", addr, size);

    const uint8_t* p = (const uint8_t*)addr;
    for (size_t i = 0; i < size; i += 4) {
        if (i + 4 <= size) {
            uint32_t insn = *(const uint32_t*)(p + i);
            hook_log("  +%03zx: %08x", i, insn);
        } else {
            /* Partial last word */
            hook_log("  +%03zx: (partial)", i);
        }
    }
}

void hook_art_router_get_debug(uint64_t* last_x0, uint64_t* miss_count) {
    if (last_x0)    *last_x0    = g_art_router_last_x0;
    if (miss_count) *miss_count = g_art_router_miss_count;
}

void hook_art_router_reset_debug(void) {
    g_art_router_last_x0 = 0;
    g_art_router_miss_count = 0;
    g_art_router_hit_count = 0;
    g_art_router_last_hit_x0 = 0;
    g_art_router_quick_hit_count = 0;
    g_art_router_quick_pass_count = 0;
    g_art_router_quick_callback_count = 0;
    g_art_router_quick_skip_count = 0;
    g_art_router_replacement_hit_count = 0;
    g_art_router_do_call_table_hit_count = 0;
    g_art_router_last_do_call_x0 = 0;
}

void hook_art_router_get_hit_debug(uint64_t* hit_count, uint64_t* last_hit_x0) {
    if (hit_count)    *hit_count    = g_art_router_hit_count;
    if (last_hit_x0)  *last_hit_x0  = g_art_router_last_hit_x0;
}

void hook_art_router_get_route_stats(uint64_t* quick_hits,
                                     uint64_t* replacement_hits,
                                     uint64_t* do_call_table_hits,
                                     uint64_t* last_do_call_x0,
                                     uint64_t* quick_pass_hits,
                                     uint64_t* quick_callback_calls,
                                     uint64_t* quick_skip_hits) {
    if (quick_hits)          *quick_hits          = g_art_router_quick_hit_count;
    if (replacement_hits)    *replacement_hits    = g_art_router_replacement_hit_count;
    if (do_call_table_hits)  *do_call_table_hits  = g_art_router_do_call_table_hit_count;
    if (last_do_call_x0)     *last_do_call_x0     = g_art_router_last_do_call_x0;
    if (quick_pass_hits)     *quick_pass_hits     = g_art_router_quick_pass_count;
    if (quick_callback_calls)*quick_callback_calls= g_art_router_quick_callback_count;
    if (quick_skip_hits)     *quick_skip_hits     = g_art_router_quick_skip_count;
}

/* ============================================================================
 * ART router thunk helpers — shared code blocks for generate_art_router_thunk
 * and hook_create_art_router_stub.
 * ============================================================================ */

/* ART-visible router frame. Keep this identical in size to ARM64
 * SaveRefsAndArgs (224 bytes): even if our fake OAT header is missed, ART's
 * native GenericJNI fallback advances by the same frame size instead of reading
 * saved registers as the next ArtMethod.
 *
 * Full callback HookContext lives in TLS; this stack frame is only the managed
 * stack-walk frame plus the raw quick-call registers needed to rebuild context.
 */
#define ROUTER_FRAME_SIZE          224
#define ROUTER_FRAME_PADDING_OFF   8
#define ROUTER_FRAME_FP_OFF        16
#define ROUTER_X1_OFF              80
#define ROUTER_SAVED_X20_OFF       136
#define ROUTER_SAVED_X30_OFF       216
#define ROUTER_FRAME_RETURN_PC_OFF 216

/* TPIDR_EL0 system register encoding */
#define SYSREG_TPIDR_EL0 0xDE82

/* Fast $orig bypass: checked BEFORE prologue (zero register save overhead).
 * Scans g_orig_bypass slots for matching thread+method, jumps to trampoline.
 * Only clobbers X16/X17 (scratch registers). */
static void emit_art_router_fast_bypass(Arm64Writer* w, uint64_t lbl_normal) {
    /* Fast exit: if no bypass active, skip scan */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_orig_bypass_active);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X17, 0);
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X17, lbl_normal);

    /* X16 = current thread ID */
    arm64_writer_put_mrs_reg(w, ARM64_REG_X16, SYSREG_TPIDR_EL0);

    for (int i = 0; i < ORIG_BYPASS_SLOTS; i++) {
        OrigBypassState* slot = &g_orig_bypass[i];
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&slot->thread);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X17, 0);
        arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X16, ARM64_REG_X17);
        uint64_t lbl_next = arm64_writer_new_label_id(w);
        arm64_writer_put_b_cond_label(w, ARM64_COND_NE, lbl_next);
        /* Thread matches — check method */
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&slot->method);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X17, 0);
        arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X17, ARM64_REG_X0);
        arm64_writer_put_b_cond_label(w, ARM64_COND_NE, lbl_next);
        /* Match! Jump to trampoline */
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&slot->thread);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, 16); /* trampoline */
        arm64_writer_put_br_reg(w, ARM64_REG_X16);
        arm64_writer_put_label(w, lbl_next);
    }
}

/* --- Fast $orig bypass slot management (called from Rust) --- */

int orig_bypass_set(uint64_t thread, uint64_t method, uint64_t trampoline) {
    for (int i = 0; i < ORIG_BYPASS_SLOTS; i++) {
        OrigBypassState* slot = &g_orig_bypass[i];
        uint64_t expected = 0;
        if (__atomic_compare_exchange_n(&slot->thread, &expected, (uint64_t)1,
                                         0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            slot->method = method;
            slot->trampoline = trampoline;
            __atomic_thread_fence(__ATOMIC_RELEASE);
            slot->thread = thread;
            __atomic_add_fetch(&g_orig_bypass_active, 1, __ATOMIC_RELEASE);
            return 0;
        }
    }
    return -1;
}

void orig_bypass_clear(uint64_t thread) {
    for (int i = 0; i < ORIG_BYPASS_SLOTS; i++) {
        OrigBypassState* slot = &g_orig_bypass[i];
        if (__atomic_load_n(&slot->thread, __ATOMIC_RELAXED) == thread) {
            __atomic_store_n(&slot->thread, 0, __ATOMIC_RELEASE);
            __atomic_sub_fetch(&g_orig_bypass_active, 1, __ATOMIC_RELEASE);
            return;
        }
    }
}

/* --- BLR fast $orig: post-callback flag (separate from entry bypass) --- */

FastOrigSlot g_fast_orig_slots[FAST_ORIG_SLOTS] = {{0}};
volatile uint64_t g_fast_orig_active = 0;
volatile uint64_t g_fast_orig_frame_thread = 0;
volatile uint64_t g_fast_orig_frame_sp = 0;

static __thread HookContext g_art_router_tls_ctx;

static HookContext* art_router_prepare_quick_context(void* frame_sp) {
    uint8_t* sp = (uint8_t*)frame_sp;
    HookContext* ctx = &g_art_router_tls_ctx;
    uint64_t thread = 0;
#if defined(__aarch64__)
    __asm__ __volatile__("mov %0, x19" : "=r"(thread));
#endif
    ctx->x[0] = *(uint64_t*)(sp + 0);
    for (int i = 1; i <= 7; i++) {
        ctx->x[i] = *(uint64_t*)(sp + ROUTER_X1_OFF + (i - 1) * 8);
    }
    for (int i = 8; i < 31; i++) {
        ctx->x[i] = 0;
    }
    ctx->x[19] = thread;
    for (int i = 20; i <= 29; i++) {
        ctx->x[i] = *(uint64_t*)(sp + ROUTER_SAVED_X20_OFF + (i - 20) * 8);
    }
    ctx->x[30] = *(uint64_t*)(sp + ROUTER_SAVED_X30_OFF);
    ctx->sp = (uint64_t)(sp + ROUTER_FRAME_SIZE);
    ctx->pc = 0;
    ctx->nzcv = 0;
    ctx->trampoline = NULL;
    for (int i = 0; i < 8; i++) {
        ctx->d[i] = *(uint64_t*)(sp + ROUTER_FRAME_FP_OFF + i * 8);
    }
    ctx->intercept_leave = 0;
    return ctx;
}

static HookContext* art_router_prepare_quick_context_preorig(void* frame_sp,
                                                             uint64_t ret_x0,
                                                             double ret_d0) {
    HookContext* ctx = art_router_prepare_quick_context(frame_sp);
    uint64_t ret_d0_bits = 0;
    memcpy(&ret_d0_bits, &ret_d0, sizeof(ret_d0_bits));
    ctx->x[16] = ret_x0;
    ctx->d[0] = ret_d0_bits;
    return ctx;
}

int fast_orig_set(uint64_t thread, uint64_t method, uint64_t trampoline) {
    for (int i = 0; i < FAST_ORIG_SLOTS; i++) {
        FastOrigSlot* slot = &g_fast_orig_slots[i];
        uint64_t expected = 0;
        if (__atomic_compare_exchange_n(&slot->thread, &expected, (uint64_t)1,
                                         0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            slot->method = method;
            slot->trampoline = trampoline;
            __atomic_thread_fence(__ATOMIC_RELEASE);
            slot->thread = thread;
            __atomic_add_fetch(&g_fast_orig_active, 1, __ATOMIC_RELEASE);
            return 0;
        }
    }
    return -1;
}

void fast_orig_clear(uint64_t thread) {
    for (int i = 0; i < FAST_ORIG_SLOTS; i++) {
        FastOrigSlot* slot = &g_fast_orig_slots[i];
        if (__atomic_load_n(&slot->thread, __ATOMIC_RELAXED) == thread) {
            __atomic_store_n(&slot->thread, 0, __ATOMIC_RELEASE);
            __atomic_sub_fetch(&g_fast_orig_active, 1, __ATOMIC_RELEASE);
            return;
        }
    }
}

uint64_t fast_orig_current_frame(uint64_t thread) {
    if (__atomic_load_n(&g_fast_orig_frame_thread, __ATOMIC_ACQUIRE) == thread) {
        return __atomic_load_n(&g_fast_orig_frame_sp, __ATOMIC_ACQUIRE);
    }
    return 0;
}

static void emit_set_fast_orig_frame(Arm64Writer* w) {
    arm64_writer_put_mrs_reg(w, ARM64_REG_X16, SYSREG_TPIDR_EL0);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_fast_orig_frame_sp);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_SP, ARM64_REG_X17, 0);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_fast_orig_frame_thread);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, 0);
}

static void emit_clear_fast_orig_frame(Arm64Writer* w) {
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_fast_orig_frame_thread);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_XZR, ARM64_REG_X17, 0);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_fast_orig_frame_sp);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_XZR, ARM64_REG_X17, 0);
}

static void emit_art_router_prologue(Arm64Writer* w) {
    /* thunk-level 计数废弃, 见 hook_engine_inline.c emit_save_hook_context 注释.
     * 计数改为只在 Rust java_hook_callback 进出点 inc/dec. */
    /* 分配整个帧 */
    arm64_writer_put_sub_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, ROUTER_FRAME_SIZE);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_SP, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_XZR, ARM64_REG_SP, ROUTER_FRAME_PADDING_OFF);

    /* Match ART ARM64 SaveRefsAndArgs exactly:
     *   +16..+72  d0-d7
     *   +80..+128 x1-x7
     *   +136..+216 x20-x29, lr
     */
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_stp_offset(w, i, i + 1, ARM64_REG_SP, ROUTER_FRAME_FP_OFF + i * 8);
    }
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_SP, 80, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X3, ARM64_REG_X4, ARM64_REG_SP, 96, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_SP, 112, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X7, ARM64_REG_X20, ARM64_REG_SP, 128, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_SP, 144, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X23, ARM64_REG_X24, ARM64_REG_SP, 160, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_SP, 176, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X27, ARM64_REG_X28, ARM64_REG_SP, 192, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X29, ARM64_REG_X30, ARM64_REG_SP, 208, ARM64_INDEX_SIGNED_OFFSET);
    /* WalkStack 根治: 在 frame 尾部 (SP + frame_size - 8) 也存一份 caller LR.
     * 这是伪 OatQuickMethodHeader 的 GetReturnPcOffset(). ART StackVisitor::WalkStack
     * advance 到下一帧时, next_pc = *(SP + frame_size - 8). 如不写, GC 在此位置读到
     * 未初始化字节 → 把垃圾 PC 交给下一帧的 GetOatQuickMethodHeader → wild branch SEGV. */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_LR, ARM64_REG_SP, ROUTER_FRAME_RETURN_PC_OFF);
    /* Load table pointer for scan */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)g_art_router_table);
}

/* Emit inline scan loop: LDR/CBZ/CMP/B.EQ/ADD/B.
 * Returns found and not_found label IDs via out-pointers. */
static void emit_art_router_scan_loop(Arm64Writer* w,
                                       uint64_t* lbl_found_out,
                                       uint64_t* lbl_not_found_out) {
    uint64_t lbl_loop = arm64_writer_new_label_id(w);
    uint64_t lbl_found = arm64_writer_new_label_id(w);
    uint64_t lbl_not_found = arm64_writer_new_label_id(w);

    arm64_writer_put_label(w, lbl_loop);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 0);
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X17, lbl_not_found);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X17, ARM64_REG_X0);
    arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_found);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X16, ARM64_REG_X16, sizeof(ArtRouterEntry));
    arm64_writer_put_b_label(w, lbl_loop);

    *lbl_found_out = lbl_found;
    *lbl_not_found_out = lbl_not_found;
}

/* 对标 Frida: 恢复全部寄存器 (prologue 的逆序，使用固定偏移) */
static void emit_art_router_restore_all(Arm64Writer* w) {
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_SP, 0);
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_ldp_offset(w, i, i + 1, ARM64_REG_SP, ROUTER_FRAME_FP_OFF + i * 8);
    }
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_SP, 80, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X3, ARM64_REG_X4, ARM64_REG_SP, 96, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_SP, 112, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X7, ARM64_REG_X20, ARM64_REG_SP, 128, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_SP, 144, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X23, ARM64_REG_X24, ARM64_REG_SP, 160, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_SP, 176, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X27, ARM64_REG_X28, ARM64_REG_SP, 192, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X29, ARM64_REG_X30, ARM64_REG_SP, 208, ARM64_INDEX_SIGNED_OFFSET);
    /* 释放帧 */
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, ROUTER_FRAME_SIZE);
    /* thunk-level dec 废弃 (见 prologue 注释) */
}

/* Debug: store X0 to g_art_router_last_x0, increment g_art_router_miss_count */
static void emit_art_router_debug_counters(Arm64Writer* w) {
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)&g_art_router_last_x0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 0);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)&g_art_router_miss_count);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 0);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X17, ARM64_REG_X17, 1);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 0);
}

static void emit_art_router_inc_counter(Arm64Writer* w, volatile uint64_t* counter) {
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)counter);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X17, 0);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X0, ARM64_REG_X0, 1);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X17, 0);
}

/* Found path: load replacement ArtMethod from table[i].replacement,
 * overwrite saved X0 with replacement, restore all regs, then jump to
 * replacement.entry_point_ (jni_trampoline).
 *
 * 对标 Frida: declaring_class_ 不在 trampoline 里同步。
 * Frida 的 find_replacement_method_from_quick_code 是纯读操作，
 * declaring_class_ 仅通过 GC 回调 (synchronize_replacement_methods) 批量同步。
 * 在 trampoline 里写 malloc 地址会导致 Scudo 堆损坏（spawn 模式已验证）。 */
/* C-callable stack check function (implemented in Rust art_controller.rs).
 * Returns 1 = normal routing, 0 = skip (callOriginal recursion). */
extern int art_router_stack_check(uint64_t replacement);

static void emit_restore_args_only(Arm64Writer* w);

static void emit_art_router_quick_callback_path(Arm64Writer* w, uint64_t lbl_quick,
                                                 uint64_t lbl_not_found,
                                                 uint64_t trampoline_target) {
    uint64_t lbl_quick_continue = arm64_writer_new_label_id(w);
    uint64_t lbl_call_original = arm64_writer_new_label_id(w);
    uint64_t lbl_return_replacement = arm64_writer_new_label_id(w);
    uint64_t lbl_preorig_callback = arm64_writer_new_label_id(w);

    arm64_writer_put_label(w, lbl_quick);

    emit_art_router_inc_counter(w, &g_art_router_quick_hit_count);

    /* X16 points to matched table entry. Load the native replacement sentinel
     * and publish it at SP+0 while the callback runs so ART StackVisitor treats
     * this router frame as native and does not look for StackMap data for the
     * original method at our generated PC. */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 8);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);

    /* Reuse the existing recursion guard. If this thread is inside $orig,
     * restore original x0 and fall through to the relocated original code. */
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X20, ARM64_REG_X16);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X21, ARM64_REG_X17);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X17);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)art_router_stack_check);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X0, lbl_quick_continue);
    emit_art_router_inc_counter(w, &g_art_router_quick_skip_count);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X20, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);
    arm64_writer_put_b_label(w, lbl_not_found);

    arm64_writer_put_label(w, lbl_quick_continue);
    emit_art_router_inc_counter(w, &g_art_router_quick_pass_count);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X20);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X17, ARM64_REG_X21);

    /* Mode 2: call original first inside the router frame, then run the
     * callback. Lua self:orig() reads the saved return value instead of
     * crossing JNI or calling quick code from a native callback stack. */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X20, 16);
    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X1, 2);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X0, ARM64_REG_X1);
    arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_preorig_callback);

    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X20, 24); /* quick_callback */
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X16, lbl_call_original);
    emit_art_router_inc_counter(w, &g_art_router_quick_callback_count);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_SP);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)art_router_prepare_quick_context);
    arm64_writer_put_blr_reg(w, ARM64_REG_X17);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X22, ARM64_REG_X0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X1, ARM64_REG_X20, 32); /* quick_user_data */
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);

    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X22, 344);
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X0, lbl_return_replacement);

    arm64_writer_put_label(w, lbl_call_original);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X20, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);
    emit_art_router_restore_all(w);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, trampoline_target);
    arm64_writer_put_br_reg(w, ARM64_REG_X16);

    arm64_writer_put_label(w, lbl_preorig_callback);
    /* ART quick code is not a C callee for our router. Do not keep router
     * state in x20-x28 across the original quick call. */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X20, ARM64_REG_SP, ROUTER_FRAME_PADDING_OFF);

    /* Keep SP+0 as the quick stack sentinel while the original runs.
     * The sentinel is a static native no-object-argument ArtMethod clone whose
     * quick entrypoint points at this generated thunk, so StackVisitor can use
     * our fake header for wwb_hook_pool PCs and ReferenceMapVisitor has no
     * object parameters to scan from the synthetic router frame. */
    emit_restore_args_only(w);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X20, 8);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X20, 0);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, trampoline_target);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X1, ARM64_REG_X0);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_SP);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)art_router_prepare_quick_context_preorig);
    arm64_writer_put_blr_reg(w, ARM64_REG_X17);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X22, ARM64_REG_X0);

    uint64_t lbl_preorig_no_callback = arm64_writer_new_label_id(w);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X20, ARM64_REG_SP, ROUTER_FRAME_PADDING_OFF);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X20, 24); /* quick_callback */
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X16, lbl_preorig_no_callback);
    emit_art_router_inc_counter(w, &g_art_router_quick_callback_count);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X22);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X1, ARM64_REG_X20, 32); /* quick_user_data */
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    arm64_writer_put_b_label(w, lbl_return_replacement);

    arm64_writer_put_label(w, lbl_preorig_no_callback);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X22, 128);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X22, 0);
    arm64_writer_put_b_label(w, lbl_return_replacement);

    arm64_writer_put_label(w, lbl_return_replacement);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X22, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_SP, 0);
    arm64_writer_put_fp_ldp_offset(w, 0, 1, ARM64_REG_X22, 280);
    arm64_writer_put_fp_stp_offset(w, 0, 1, ARM64_REG_SP, ROUTER_FRAME_FP_OFF);
    emit_art_router_restore_all(w);
    arm64_writer_put_ret(w);
}

static void emit_art_router_found_path(Arm64Writer* w, uint64_t lbl_found,
                                        uint32_t quickcode_offset,
                                        uint64_t current_pc_hint,
                                        uint64_t lbl_not_found,
                                        uint64_t trampoline_target) {
    (void)current_pc_hint;

    arm64_writer_put_label(w, lbl_found);

    /* Debug: increment hit counter */
    emit_art_router_inc_counter(w, &g_art_router_hit_count);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_art_router_last_hit_x0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X17, 0);

    uint64_t lbl_quick = arm64_writer_new_label_id(w);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 16);
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X0, lbl_quick);

    emit_art_router_inc_counter(w, &g_art_router_replacement_hit_count);

    /* X16 points to matched table entry; load replacement ArtMethod* from offset 8 */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 8);

    /* WalkStack 根治: 提前把 replacement 写到 SP+0, 覆盖 prologue 的 original.
     * 这样 ART StackVisitor 在本线程 (或 peer 线程) 读 *cur_quick_frame = *SP
     * 时立即看到 replacement (K_ACC_NATIVE) → GetDexPc 走 native 早退路径.
     * 在 BLR art_router_stack_check 之前执行, 避免 BLR 进入 Rust 后被其他线程
     * suspend 时 SP+0 还是 original (non-native) → 触发 StackMap not found abort. */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);

    /* --- Stack check: 防止 callOriginal 递归 (对标 Frida) ---
     * 保存 X16(table entry), X17(replacement) 到 callee-saved X20, X21 (已在 prologue 保存)。
     * 调用 art_router_stack_check(replacement): 返回 0 表示递归 → 走 not_found 路径。
     * NOTE: 递归 (not_found) 时 restore_all 会用 SP+0 的值覆盖 x0, 所以要
     * 在 CBZ 后、走 not_found 分支前先把 SP+0 恢复成 original (否则 x0 变 replacement
     * 破坏原方法调用约定). */
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X20, ARM64_REG_X16);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X21, ARM64_REG_X17);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X17);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)art_router_stack_check);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    /* 递归路径: 恢复 SP+0 为 original (table entry 的 first u64), 再跳 not_found.
     * X20 仍是 table entry 指针, 读 [X20, 0] 得 original, 写回 SP+0. */
    uint64_t lbl_found_continue = arm64_writer_new_label_id(w);
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X0, lbl_found_continue);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X20, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);
    arm64_writer_put_b_label(w, lbl_not_found);
    arm64_writer_put_label(w, lbl_found_continue);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X20);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X17, ARM64_REG_X21);

    /* 同步 declaring_class_ (offset 0, 4 bytes): original → replacement */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 0);  /* X0 = original */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_W0, ARM64_REG_X0, 0);   /* W0 = original->declaring_class_ */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_W0, ARM64_REG_X17, 0);  /* replacement->declaring_class_ = W0 */

    /* SP+0 已提前置为 replacement (见上). restore_all 从 SP+0 读回 x0 → x0 = replacement. */

    /* Restore all regs — X0 now holds replacement ArtMethod*
     * (dec 在 restore_all 尾部) */
    emit_art_router_restore_all(w);

    /* Load replacement.entry_point_ (= jni_trampoline) 到 x16, BR 出 thunk */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X0, quickcode_offset);
    arm64_writer_put_br_reg(w, ARM64_REG_X16);

    emit_art_router_quick_callback_path(w, lbl_quick, lbl_not_found, trampoline_target);
}

/* Not-found path: 对标 Frida — 恢复全部寄存器 → relocated original instructions → jump back.
 * Shared by generate_art_router_thunk and hook_create_art_router_stub. */
static void emit_art_router_not_found_path(Arm64Writer* w, uint64_t lbl_not_found,
                                            uint64_t fallback_target) {
    arm64_writer_put_label(w, lbl_not_found);
    emit_art_router_debug_counters(w);
    /* 恢复全部寄存器（含原始 x0, dec 在 restore_all 尾部） */
    emit_art_router_restore_all(w);
    /* Jump to fallback target (relocated original or trampoline) */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, fallback_target);
    arm64_writer_put_br_reg(w, ARM64_REG_X16);
}

/* ============================================================================
 * BLR variant helpers
 * ============================================================================ */

/* Restore quick argument regs from the ART-visible router frame. */
static void emit_restore_args_only(Arm64Writer* w) {
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_ldp_offset(w, i, i + 1, ARM64_REG_SP,
            ROUTER_FRAME_FP_OFF + i * 8);
    }
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_SP, 80, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X3, ARM64_REG_X4, ARM64_REG_SP, 96, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_SP, 112, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X7, ARM64_REG_SP, 128);
}

/* Restore callee-saved regs (x20-x29, LR) from frame + pop frame.
 * Clobbers NO scratch regs (x16/x17 untouched). */
static void emit_restore_callee_and_pop(Arm64Writer* w) {
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X20, ARM64_REG_SP, 136);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_SP, 144, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X23, ARM64_REG_X24, ARM64_REG_SP, 160, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_SP, 176, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X27, ARM64_REG_X28, ARM64_REG_SP, 192, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X29, ARM64_REG_LR, ARM64_REG_SP, 208, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, ROUTER_FRAME_SIZE);
}

/* BLR variant of found path for Layer 3 per-method thunks.
 *
 * Key difference from BR variant: keeps frame on stack, uses BLR to call replacement,
 * then post-callback checks if fast $orig was requested.
 *   - If yes: restore original Quick regs from frame, BR trampoline (zero JNI overhead)
 *   - If no: return callback value to caller
 *
 * trampoline_target: relocated original instructions (known at thunk generation time).
 * Stored in the router frame to survive ART quick/JNI trampolines. Do not rely
 * on x20/x22 being preserved across the BLR: ART quick stubs are not ordinary
 * C callees for our purposes. */
static void emit_art_router_found_path_blr(Arm64Writer* w, uint64_t lbl_found,
                                            uint32_t quickcode_offset,
                                            uint64_t lbl_not_found,
                                            uint64_t trampoline_target) {
    arm64_writer_put_label(w, lbl_found);

    /* Debug: increment hit counter */
    emit_art_router_inc_counter(w, &g_art_router_hit_count);
    emit_art_router_inc_counter(w, &g_art_router_replacement_hit_count);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_art_router_last_hit_x0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X17, 0);

    /* Load replacement ArtMethod* from table entry offset 8 */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 8);

    /* WalkStack: write replacement to SP+0 early (same as BR variant) */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);

    /* --- Stack check (identical to BR variant) --- */
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X20, ARM64_REG_X16);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X21, ARM64_REG_X17);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X17);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)art_router_stack_check);
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);
    uint64_t lbl_found_continue = arm64_writer_new_label_id(w);
    arm64_writer_put_cbnz_reg_label(w, ARM64_REG_X0, lbl_found_continue);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X20, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_SP, 0);
    arm64_writer_put_b_label(w, lbl_not_found);
    arm64_writer_put_label(w, lbl_found_continue);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X20);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X17, ARM64_REG_X21);

    /* Sync declaring_class_ (same as BR variant) */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 0);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_W0, ARM64_REG_X0, 0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_W0, ARM64_REG_X17, 0);

    /* === BLR-specific: prepare frame state for post-callback === */

    /* Load replacement.entry_point_ */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, quickcode_offset);

    /* Restore argument regs from frame (don't pop, don't restore callee-saved) */
    emit_restore_args_only(w);

    /* Expose the router frame to Rust while the replacement callback is active.
     * If callback requests fast orig, Rust patches object slots in this frame
     * from live JNI transition refs before returning to this post-callback code. */
    emit_set_fast_orig_frame(w);

    /* BLR: call replacement, frame stays on stack */
    arm64_writer_put_blr_reg(w, ARM64_REG_X16);

    /* === Post-callback: check fast $orig flag ===
     * x0 = callback return value (from JNI)
     * SP → art_router frame (intact, never popped) */

    uint64_t lbl_no_orig = arm64_writer_new_label_id(w);
    uint64_t lbl_do_orig = arm64_writer_new_label_id(w);

    /* Quick check: g_fast_orig_active == 0 → no fast orig */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_fast_orig_active);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X17, 0);
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X17, lbl_no_orig);

    /* Scan slots for current thread match */
    arm64_writer_put_mrs_reg(w, ARM64_REG_X16, SYSREG_TPIDR_EL0);
    for (int i = 0; i < FAST_ORIG_SLOTS; i++) {
        FastOrigSlot* slot = &g_fast_orig_slots[i];
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&slot->thread);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X17, 0);
        arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X16, ARM64_REG_X17);
        arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_do_orig);
    }
    arm64_writer_put_b_label(w, lbl_no_orig);

    /* === do_orig: restore original Quick regs, BR trampoline === */
    arm64_writer_put_label(w, lbl_do_orig);

    emit_clear_fast_orig_frame(w);

    /* Clear matched slot: scan and zero (X16 = current TPIDR_EL0) */
    for (int i = 0; i < FAST_ORIG_SLOTS; i++) {
        FastOrigSlot* slot = &g_fast_orig_slots[i];
        uint64_t lbl_skip = arm64_writer_new_label_id(w);
        arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&slot->thread);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X17, 0);
        arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X16, ARM64_REG_X0);
        arm64_writer_put_b_cond_label(w, ARM64_COND_NE, lbl_skip);
        arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_XZR, ARM64_REG_X17, 0);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X20, ARM64_REG_X17, 8);
        arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X21, ARM64_REG_X17, 16);
        arm64_writer_put_label(w, lbl_skip);
    }
    /* Decrement active */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_fast_orig_active);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, 0);
    arm64_writer_put_sub_reg_reg_imm(w, ARM64_REG_X16, ARM64_REG_X16, 1);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, 0);

    /* Debug hit counter */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X17, (uint64_t)&g_orig_bypass_hit);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, 0);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X16, ARM64_REG_X16, 1);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17, 0);

    emit_restore_args_only(w);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X20);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X21);

    /* Restore callee-saved + pop frame */
    emit_restore_callee_and_pop(w);

    /* BR trampoline → original method → RET to caller */
    arm64_writer_put_br_reg(w, ARM64_REG_X16);

    /* === no_orig: return callback value === */
    arm64_writer_put_label(w, lbl_no_orig);

    /* Save callback return value (x0) to X16 */
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X0);

    emit_clear_fast_orig_frame(w);

    /* Restore callee-saved + pop frame */
    emit_restore_callee_and_pop(w);

    /* Restore callback return value */
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X0, ARM64_REG_X16);

    /* RET to caller */
    arm64_writer_put_ret(w);
}

/* ============================================================================
 * 伪 OatQuickMethodHeader 前置 (WalkStack 根治)
 *
 * Android 16 (API 36) OatQuickMethodHeader 布局 (libart_base_commit):
 *   class PACKED(4) OatQuickMethodHeader {
 *       uint32_t code_info_offset_;     // offset from code_ back to CodeInfo
 *       uint8_t  code_[0];              // actual method code starts here
 *   };
 *
 * ART 的 GetOatQuickMethodHeader(pc) 逻辑:
 *   header = FromEntryPoint(entry_point) = entry_point - sizeof(header) = entry_point - 4
 *   if (header->Contains(pc))  // code <= pc <= code + GetCodeSize()
 *     return header
 *
 * GetDexPc 在 method->IsNative() 时直接 return kDexNoIndex, 不访问 StackMap.
 * 所以我们:
 *   1. 在 thunk 前放 CodeInfo 字节 + 4B 伪 header
 *   2. code_info_offset_ = 距 code_ 前的 CodeInfo 字节数
 *   3. code_size_ 写 thunk 实际字节数 (body_size)
 *   4. thunk 一开头就把 replacement (native ArtMethod*) 写到 SP+0
 *      → WalkStack 读 *SP = replacement → IsNative=true → ToDexPc 走 native 早退路径
 *
 * The fake CodeInfo must describe the same callee-save layout as ART ARM64
 * SaveRefsAndArgs. If the spill masks are zero, StackVisitor advances by the
 * right frame size but does not refill caller context registers, so the next
 * compiled Java frame can treat stale scalar registers (for example 0x1) as
 * object roots during GC.
 * ============================================================================ */

#define FAKE_OAT_CODEINFO_BYTES 16
#define FAKE_OAT_PREFIX_SIZE (FAKE_OAT_CODEINFO_BYTES + 4)

/* router thunk frame_size (SUB SP, #0xE0 -> 224) / kStackAlignment (16) = 14 */
#define FAKE_PACKED_FRAME_SIZE 14
#define FAKE_CORE_SPILL_MASK \
    ((1u << 30) | \
     (1u << 29) | (1u << 28) | (1u << 27) | (1u << 26) | (1u << 25) | \
     (1u << 24) | (1u << 23) | (1u << 22) | (1u << 21) | (1u << 20) | \
     (1u << 7)  | (1u << 6)  | (1u << 5)  | (1u << 4)  | (1u << 3)  | \
     (1u << 2)  | (1u << 1))
#define FAKE_FP_SPILL_MASK 0xffu

static void fake_codeinfo_write_bits(uint8_t* buf, size_t* bit_offset,
                                     uint32_t value, size_t bit_count) {
    for (size_t i = 0; i < bit_count; i++) {
        if ((value >> i) & 1u) {
            size_t bit = *bit_offset + i;
            buf[bit >> 3] |= (uint8_t)(1u << (bit & 7));
        }
    }
    *bit_offset += bit_count;
}

static void fake_codeinfo_write_interleaved_varints(uint8_t* buf,
                                                    const uint32_t values[7],
                                                    const uint8_t widths[7]) {
    size_t bit_offset = 0;
    for (int i = 0; i < 7; i++) {
        uint32_t value = values[i];
        uint32_t marker = value <= 11u ? value : (11u + widths[i]);
        fake_codeinfo_write_bits(buf, &bit_offset, marker, 4);
    }
    for (int i = 0; i < 7; i++) {
        if (values[i] > 11u) {
            fake_codeinfo_write_bits(buf, &bit_offset, values[i], (size_t)widths[i] * 8u);
        }
    }
}

/* CodeInfo 编码: 7 个 interleaved 4-bit varint + 追加 32-bit 值 (当 nibble >= 12).
 * 字段顺序与 art::CodeInfo::ForEachHeaderField 一致:
 *   flags, code_size, packed_frame_size, core_spill_mask, fp_spill_mask,
 *   number_of_dex_registers, bit_table_flags.
 */
static void encode_fake_codeinfo_v2(uint8_t buf[FAKE_OAT_CODEINFO_BYTES],
                                     uint32_t code_size, uint32_t frame_packed) {
    memset(buf, 0, FAKE_OAT_CODEINFO_BYTES);
    uint32_t values[7] = {
        0,
        code_size,
        frame_packed,
        FAKE_CORE_SPILL_MASK,
        FAKE_FP_SPILL_MASK,
        0,
        0,
    };
    uint8_t widths[7] = {
        0,
        4, /* code_size */
        1, /* packed_frame_size = 14 */
        4, /* core_spill_mask */
        1, /* fp_spill_mask = 0xff */
        0,
        0,
    };
    fake_codeinfo_write_interleaved_varints(buf, values, widths);
}

/* 填充 thunk 前 16 字节: [CodeInfo 12B][OatQuickMethodHeader 4B].
 * code_size covers the whole executable body allocation, not just the current
 * writer offset. If ART fails Contains(pc) for a router return PC, native
 * sentinel frames fall back to GenericJNI frame size. The router frame is kept
 * at the same 224-byte size so both paths advance identically. */
static void backfill_fake_oat_header(void* thunk_mem, uint32_t code_size) {
    uint8_t* p = (uint8_t*)thunk_mem;
    encode_fake_codeinfo_v2(p, code_size, FAKE_PACKED_FRAME_SIZE);
    /* code_info_offset_ is measured from code_ (body start) back to CodeInfo,
     * so it includes both the CodeInfo bytes and the 4-byte header. */
    uint32_t header_data = FAKE_OAT_PREFIX_SIZE;
    memcpy(p + FAKE_OAT_CODEINFO_BYTES, &header_data, sizeof(uint32_t));
}

/* ============================================================================
 * ART router thunk generation (uses helpers above)
 *
 * not_found path: jump to trampoline_target (relocated original instructions).
 * X16/X17 are NOT restored (clobbered by thunk, caller uses X17 for jump-back).
 *
 * 布局: [12B 伪 OAT header/CodeInfo] [thunk body]
 * entry_point 指向 thunk + 12 (body start).
 * ============================================================================ */

static size_t generate_art_router_thunk(void* thunk_mem, size_t thunk_alloc,
                                         void* trampoline_target,
                                         uint32_t quickcode_offset,
                                         uint64_t current_pc_hint,
                                         int use_blr) {
    /* 前 12 字节是 CodeInfo+header 占位, 最后 backfill.
     * Arm64Writer 初始化到 body 起点 (thunk_mem + 12). */
    if (thunk_alloc < FAKE_OAT_PREFIX_SIZE + 64) {
        hook_log("[art_router] thunk_alloc %zu too small for fake header", thunk_alloc);
        return 0;
    }
    void* body_mem = (uint8_t*)thunk_mem + FAKE_OAT_PREFIX_SIZE;
    size_t body_alloc = thunk_alloc - FAKE_OAT_PREFIX_SIZE;

    Arm64Writer w;
    arm64_writer_init(&w, body_mem, (uint64_t)body_mem, body_alloc);

    /* Fast $orig bypass — checked BEFORE prologue (zero register save overhead).
     * This handles the JNI-path $orig re-entry (orig_bypass_set from Rust). */
    uint64_t lbl_normal_path = arm64_writer_new_label_id(&w);
    emit_art_router_fast_bypass(&w, lbl_normal_path);
    arm64_writer_put_label(&w, lbl_normal_path);

    emit_art_router_prologue(&w);

    uint64_t lbl_found, lbl_not_found;
    emit_art_router_scan_loop(&w, &lbl_found, &lbl_not_found);

    if (use_blr) {
        /* BLR variant: keeps frame on stack, calls trampoline post-callback if $orig set */
        emit_art_router_found_path_blr(&w, lbl_found, quickcode_offset, lbl_not_found,
                                        (uint64_t)trampoline_target);
    } else {
        emit_art_router_found_path(&w, lbl_found, quickcode_offset, current_pc_hint,
                                   lbl_not_found, (uint64_t)trampoline_target);
    }

    /* === not_found path: fall through to trampoline === */
    emit_art_router_not_found_path(&w, lbl_not_found, (uint64_t)trampoline_target);

    arm64_writer_flush(&w);
    size_t body_size = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    hook_log("[art_router] thunk body_size=%zu body_alloc=%zu (alloc=%zu, use_blr=%d)",
             body_size, body_alloc, thunk_alloc, use_blr);

    /* 回填伪 OAT header + CodeInfo (Contains(pc) 覆盖整个 thunk body allocation) */
    backfill_fake_oat_header(thunk_mem, (uint32_t)body_alloc);

    /* 返回总字节数 (含 12B 前缀), 调用方用于 hook_flush_cache */
    return FAKE_OAT_PREFIX_SIZE + body_size;
}

/* ============================================================================
 * Tiny ART trampoline resolver
 *
 * Some ART entry points (e.g. quick_generic_jni_trampoline) are tiny 8-byte
 * trampolines:
 *   LDR Xt, [X19, #imm]
 *   BR Xt
 *
 * X19 holds the Thread* pointer (current ART thread).  We resolve the actual
 * target by reading Thread*->field at the given offset.
 *
 * jni_env: JNIEnv* pointer.  On Android, JNIEnv* == Thread* + some offset.
 *          Typically Thread* = JNIEnv* - 0 (JNIEnv is the first field).
 * ============================================================================ */

void* resolve_art_trampoline(void* target, void* jni_env) {
    if (!target || !jni_env) return target;

    /* Read first two instructions */
    uint8_t buf[8];
    if (read_target_safe(target, buf, 8) != 0)
        return target;

    uint32_t insn0 = *(uint32_t*)buf;
    uint32_t insn1 = *(uint32_t*)(buf + 4);

    /* Check pattern: LDR Xt, [X19, #imm]  = 1111 1001 01 imm12 10011 Rt
     * Mask: 0xFFC003E0, expect: 0xF9400260 (base=X19, any Rt, any imm12) */
    if ((insn0 & 0xFFC003E0) != 0xF9400260)
        return target;

    /* Check: BR Xt — 1101 0110 0001 1111 0000 00 Rn 00000
     * Mask: 0xFFFFFC1F, expect: 0xD61F0000 */
    uint32_t rt_ldr = insn0 & 0x1F;
    uint32_t rn_br  = (insn1 >> 5) & 0x1F;
    if ((insn1 & 0xFFFFFC1F) != 0xD61F0000)
        return target;
    if (rt_ldr != rn_br)
        return target;

    /* Extract unsigned imm12 (scaled by 8 for 64-bit LDR) */
    uint32_t imm12 = (insn0 >> 10) & 0xFFF;
    uint64_t offset = (uint64_t)imm12 * 8;

    /* JNIEnvExt layout: [0]=JNINativeInterface*, [8]=self_ (Thread*)
     * We need Thread*, not JNIEnv* itself. */
    uint64_t thread = *(uint64_t*)((uint64_t)jni_env + 8);
    uint64_t resolved = *(uint64_t*)(thread + offset);

    hook_log("[art_router] resolve_art_trampoline: %p → LDR X%d,[X19,#%llu]; BR X%d → %llx",
             target, rt_ldr, (unsigned long long)offset, rn_br,
             (unsigned long long)resolved);

    return (void*)resolved;
}

/* ============================================================================
 * hook_install_art_router — inline hook with ART router thunk
 *
 * Similar to hook_install() but instead of a simple replacement, installs a
 * router thunk that scans g_art_router_table inline.
 * ============================================================================ */

void* hook_install_art_router(void* target, uint32_t quickcode_offset,
                               int stealth, void* jni_env,
                               void** out_hooked_target,
                               int skip_resolve,
                               uint64_t current_pc_hint,
                               int use_blr) {
    if (!g_engine.initialized || !target) {
        return NULL;
    }

    /* Resolve tiny ART trampolines (LDR+BR 8 bytes) to actual target */
    if (!skip_resolve) {
        void* resolved = resolve_art_trampoline(target, jni_env);
        if (resolved != target) {
            hook_log("[art_router] resolved %p → %p", target, resolved);
            target = resolved;
        }
    }

    /* Report the actual hooked address back to the caller for cleanup */
    if (out_hooked_target) {
        *out_hooked_target = target;
    }

    pthread_mutex_lock(&g_engine.lock);

    /* Check if already hooked — return existing trampoline */
    HookEntry* existing = find_hook(target);
    if (existing) {
        void* trampoline = existing->trampoline;
        pthread_mutex_unlock(&g_engine.lock);
        return trampoline;
    }

    HookEntry* entry = setup_hook_entry(target);
    if (!entry) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Allocate thunk (router code — larger than default).
     * hook_alloc_near 按 ±128MB → ±4GB → 任意 三层分配。 */
    size_t art_thunk_alloc = 4096;
    if (!entry->thunk || entry->thunk_alloc < art_thunk_alloc) {
        entry->thunk = hook_alloc_near(art_thunk_alloc, target);
        entry->thunk_alloc = art_thunk_alloc;
    }
    if (!entry->thunk) {
        free_entry(entry);
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    if (build_trampoline(entry, 0) < 0) {
        free_entry(entry);
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Generate router thunk — not_found path jumps to trampoline.
     * Thunk 布局: [12B 伪 OAT header/CodeInfo] [thunk body].
     * thunk_size 返回值含 12B 前缀. entry_point/patch_target 指向 body start. */
    size_t thunk_size = generate_art_router_thunk(
        entry->thunk, art_thunk_alloc,
        entry->trampoline, quickcode_offset, current_pc_hint, use_blr);
    if (thunk_size == 0) {
        free_entry(entry);
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Patch target to jump to router thunk body (跳过 12B 伪 header) */
    void* patch_dest = (uint8_t*)entry->thunk + FAKE_OAT_PREFIX_SIZE;
    if (patch_target(target, patch_dest, stealth, entry) != 0) {
        free_entry(entry);
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    finalize_hook(entry, entry->thunk, thunk_size);

    void* trampoline = entry->trampoline;
    pthread_mutex_unlock(&g_engine.lock);

    hook_log("[art_router] installed: target=%p, thunk=%p, trampoline=%p",
             target, entry->thunk, trampoline);

    return trampoline;
}

void* hook_art_router_get_thunk_body(void* target) {
    if (!g_engine.initialized || !target) {
        return NULL;
    }

    pthread_mutex_lock(&g_engine.lock);
    HookEntry* entry = find_hook(target);
    void* body = NULL;
    if (entry && entry->thunk) {
        body = (uint8_t*)entry->thunk + FAKE_OAT_PREFIX_SIZE;
    }
    pthread_mutex_unlock(&g_engine.lock);
    return body;
}

/* ============================================================================
 * hook_create_art_router_stub — standalone ART router (no inline patching)
 *
 * Creates a thunk that scans g_art_router_table for X0, and if not found,
 * jumps to fallback_target.  The caller writes the returned address into
 * ArtMethod.entry_point_ directly.
 * ============================================================================ */

void* hook_create_art_router_stub(uint64_t fallback_target,
                                   uint32_t quickcode_offset) {
    if (!g_engine.initialized || !fallback_target) {
        return NULL;
    }

    pthread_mutex_lock(&g_engine.lock);

    /* stub 通过 ArtMethod.entry_point_ 指针间接调用，不需要 near.
     * 布局: [12B 伪 OAT header/CodeInfo] [stub body]. 返回 body 起点. */
    size_t stub_alloc = 2048;
    void* stub_mem = hook_alloc(stub_alloc);
    if (!stub_mem) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    void* body_mem = (uint8_t*)stub_mem + FAKE_OAT_PREFIX_SIZE;
    size_t body_alloc = stub_alloc - FAKE_OAT_PREFIX_SIZE;

    Arm64Writer w;
    arm64_writer_init(&w, body_mem, (uint64_t)body_mem, body_alloc);

    /* Fast $orig bypass */
    uint64_t lbl_normal_path = arm64_writer_new_label_id(&w);
    emit_art_router_fast_bypass(&w, lbl_normal_path);
    arm64_writer_put_label(&w, lbl_normal_path);

    emit_art_router_prologue(&w);

    uint64_t lbl_found, lbl_not_found;
    emit_art_router_scan_loop(&w, &lbl_found, &lbl_not_found);
    emit_art_router_found_path(&w, lbl_found, quickcode_offset, 0,
                               lbl_not_found, fallback_target);

    /* === not_found path: jump to fallback === */
    emit_art_router_not_found_path(&w, lbl_not_found, fallback_target);

    arm64_writer_flush(&w);
    size_t body_size = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    /* 回填 16B 伪 OAT header + CodeInfo */
    backfill_fake_oat_header(stub_mem, (uint32_t)body_alloc);

    hook_flush_cache(stub_mem, FAKE_OAT_PREFIX_SIZE + body_size);

    pthread_mutex_unlock(&g_engine.lock);

    hook_log("[art_router] stub created: %p (body=%p, fallback=%llx, body_size=%zu)",
             stub_mem, body_mem, (unsigned long long)fallback_target, body_size);

    return body_mem;  /* entry_point 指向 body, 前 12B 是伪 OAT header */
}

/* ============================================================================
 * C-side GC synchronization — 对标 Frida synchronize_replacement_methods
 *
 * 遍历 g_art_router_table，对每个 original/replacement 对:
 * 1. 复制 declaring_class_ (offset 0, 4B) from original → replacement
 * 2. 如果 original.quickCode == nterp → 降级为 interpreter_bridge
 * ============================================================================ */
void hook_art_synchronize_replacement_methods(
    uint32_t quickcode_offset,
    uint64_t nterp_entrypoint,
    uint64_t interp_bridge) {
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        uint64_t original = g_art_router_table[i].original;
        uint64_t replacement = g_art_router_table[i].replacement;
        if (original == 0) break;
        if (replacement == 0) continue;

        /* 1. declaring_class_ 同步 */
        uint32_t declaring_class = *(volatile uint32_t*)(uintptr_t)original;
        *(volatile uint32_t*)(uintptr_t)replacement = declaring_class;

        /* 2. nterp → interpreter_bridge 降级 */
        if (nterp_entrypoint != 0 && quickcode_offset != 0) {
            volatile uint64_t* ep = (volatile uint64_t*)((uintptr_t)original + quickcode_offset);
            if (*ep == nterp_entrypoint && interp_bridge != 0) {
                *ep = interp_bridge;
            }
        }
    }
}
