// nyx_diag.c  -  READ-ONLY diagnostic plugin for GoldHEN
// Target : PvZ Battle for Neighborville, CUSA10852, game v1.12
// Loader : GoldHEN v2.4b18 (plugin SDK template from GoldHEN_Plugins_SDK)
//
// What it does
//   Every 3 seconds it reads two globals from the game and, if they changed,
//   appends them to /data/nyx_diag.log:
//     0x07688460  (qword)  candidate "ctx"/manager pointer
//     0x0705c6d0  (dword)  candidate session tag
//   plus a 0x80-byte hex dump of whatever the first one points at.
//
// What it does NOT do
//   - no hooks, no code patching, no memory writes to the game
//   - no network, nothing sent to any server
//   - every game read goes through safe_read(), so a bad pointer can't crash the game
//
// Offsets are Ghidra addresses of the eboot (image base 0). They are only valid
// for the exact eboot that is open in Ghidra (v1.12).
//
// Usage
//   1. Put this file in a plugin project from the GoldHEN plugin SDK samples
//      (replace the sample's main .c; keep its Makefile/linker setup).
//   2. Build, copy the .prx to /data/GoldHEN/plugins/
//   3. Add to /data/GoldHEN/plugins.ini:
//        [CUSA10852]
//        /data/GoldHEN/plugins/nyx_diag.prx
//   4. Start the game, go online, enter a lobby or a match, play ~1 minute,
//      then send me /data/nyx_diag.log
//
// NOTE: written without a PS4 to test on. Header names and the module-info call
// follow the OpenOrbis/GoldHEN SDK but may need small adjustments to match your
// SDK checkout.

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <orbis/libkernel.h>
#include <GoldHEN.h>

#define attr_public __attribute__((visibility("default")))

attr_public const char *g_pluginName = "nyx_diag";
attr_public const char *g_pluginDesc = "Read-only Blaze session diagnostics";
attr_public const char *g_pluginAuth = "nyx";
attr_public uint32_t g_pluginVersion = 0x00000100;

// ---- Ghidra offsets (eboot, base 0) ---------------------------------------
#define OFF_CTX_GLOBAL 0x07688460ull  // qword
#define OFF_TAG_GLOBAL 0x0705c6d0ull  // dword

#define LOG_PATH "/data/nyx_diag.log"

static uint64_t g_base = 0;
static volatile int g_run = 1;

// Reads n bytes from p without risking a fault: the kernel copies through a pipe
// and returns an error (EFAULT) for unreadable memory.
static int safe_read(const void *p, void *out, size_t n) {
  int fds[2];
  if (n == 0 || n > 4096 || pipe(fds) != 0)
    return 0;
  int ok = 0;
  if (write(fds[1], p, n) == (ssize_t)n && read(fds[0], out, n) == (ssize_t)n)
    ok = 1;
  close(fds[0]);
  close(fds[1]);
  return ok;
}

static void logf_(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void logf_(const char *fmt, ...) {
  FILE *f = fopen(LOG_PATH, "a");
  if (!f)
    return;
  __builtin_va_list ap;
  __builtin_va_start(ap, fmt);
  vfprintf(f, fmt, ap);
  __builtin_va_end(ap);
  fclose(f);
}

static void hexdump(const char *label, uint64_t addr, size_t n) {
  uint8_t buf[0x100];
  if (n > sizeof buf)
    n = sizeof buf;
  if (!safe_read((const void *)addr, buf, n)) {
    logf_("  %s @ 0x%llx : unreadable\n", label, (unsigned long long)addr);
    return;
  }
  logf_("  %s @ 0x%llx\n", label, (unsigned long long)addr);
  for (size_t i = 0; i < n; i += 16) {
    char line[128];
    int o = snprintf(line, sizeof line, "    +%02zx:", i);
    for (size_t j = 0; j < 16 && i + j < n; j++)
      o += snprintf(line + o, sizeof line - o, " %02x", buf[i + j]);
    logf_("%s\n", line);
  }
}

// Base address of the main module (eboot). Falls back to the usual retail value.
static uint64_t find_base(void) {
  SceKernelModule mods[64];
  size_t count = 0;
  if (sceKernelGetModuleList(mods, 64, &count) == 0 && count > 0) {
    SceKernelModuleInfo info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (sceKernelGetModuleInfo(mods[0], &info) == 0 && info.segmentInfo[0].address)
      return (uint64_t)info.segmentInfo[0].address;
  }
  return 0x400000ull;
}

static void *poll_thread(void *arg) {
  (void)arg;
  uint64_t last_ctx = ~0ull;
  uint32_t last_tag = ~0u;

  while (g_run) {
    uint64_t ctx = 0;
    uint32_t tag = 0;
    int okc = safe_read((const void *)(g_base + OFF_CTX_GLOBAL), &ctx, sizeof ctx);
    int okt = safe_read((const void *)(g_base + OFF_TAG_GLOBAL), &tag, sizeof tag);

    if (okc && okt && (ctx != last_ctx || tag != last_tag)) {
      logf_("---- change ----\n");
      logf_("base      = 0x%llx\n", (unsigned long long)g_base);
      logf_("ctx global = 0x%llx\n", (unsigned long long)ctx);
      logf_("tag global = 0x%x (%u)\n", tag, tag);
      if (ctx > 0x10000) {
        hexdump("*ctx", ctx, 0x80);
        uint64_t p10 = 0;  // game code reads ctx+0x10 as the dispatch target
        if (safe_read((const void *)(ctx + 0x10), &p10, sizeof p10) && p10 > 0x10000)
          hexdump("*(ctx+0x10)", p10, 0x40);
      }
      last_ctx = ctx;
      last_tag = tag;
    }
    sceKernelSleep(3);
  }
  return NULL;
}

attr_public int32_t plugin_load(int32_t argc, const char *argv[]) {
  (void)argc;
  (void)argv;
  g_base = find_base();
  logf_("nyx_diag loaded, base = 0x%llx\n", (unsigned long long)g_base);

  ScePthread th;
  scePthreadCreate(&th, NULL, poll_thread, NULL, "nyx_diag");
  return 0;
}

attr_public int32_t plugin_unload(int32_t argc, const char *argv[]) {
  (void)argc;
  (void)argv;
  g_run = 0;
  return 0;
}
