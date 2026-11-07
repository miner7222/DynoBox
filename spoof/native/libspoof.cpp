// SPDX-License-Identifier: Apache-2.0
//
// Zygote-preload per-app property spoofing for DynoBox `--add-spoof`.
//
// The 64-bit zygote executable (`/system/bin/app_process64`) carries this
// library as its first DT_NEEDED entry, so the dynamic linker maps it before
// libandroid_runtime.so. The older LD_PRELOAD path is ignored when the zygote
// runs with AT_SECURE=1 and is no longer required.
//
// It replaces AndroidRuntime::startReg (called through the PLT by
// libandroid_runtime) and registers a replacement for
// ZygoteInit.nativeZygoteInit. That native method runs in every app process
// after fork, before the Application is created; the replacement matches
// /proc/self/cmdline against system/etc/spoof/spoof.prop and applies the
// matching property overrides for that process only.
//
// The library also answers reads of ro.vendor.config.lgsi.customize.usage from
// persist.sys.config.model_cust, which is how the developer-options edition
// toggle switches the factory customize token without touching persist. That
// token has no entry in any prop file, so `__system_property_find` is
// interposed as well: lookups must succeed for the read hooks to be reached.
//
// Build with the Android NDK:
//   ./build.sh

#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>

#define LOG_TAG "spoof"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

constexpr const char* kSpoofPath = "/system/etc/spoof/spoof.prop";
constexpr size_t kMaxSpoofBytes = 1024 * 1024;
constexpr const char* kStartRegSymbol =
        "_ZN7android14AndroidRuntime8startRegEP7_JNIEnv";
constexpr char kEditionProp[] = "ro.vendor.config.lgsi.customize.usage";
constexpr char kEditionAlias[] = "MINGCHAO";
constexpr const char* kEditionSwitch = "persist.sys.config.model_cust";

using PropMap = std::unordered_map<std::string, std::string>;
std::unordered_map<std::string, PropMap> g_spoof_apps;
const PropMap* g_overrides = nullptr;

std::string trim(std::string value) {
    const auto start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

bool read_file(const std::string& path, std::string& out, size_t limit) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    out.clear();
    char buffer[4096];
    ssize_t read_bytes = 0;
    while ((read_bytes = read(fd, buffer, sizeof(buffer))) > 0) {
        if (out.size() + static_cast<size_t>(read_bytes) > limit) {
            close(fd);
            out.clear();
            return false;
        }
        out.append(buffer, static_cast<size_t>(read_bytes));
    }
    close(fd);
    return read_bytes == 0 && !out.empty();
}

bool load_spoof_config() {
    std::string text;
    if (!read_file(kSpoofPath, text, kMaxSpoofBytes)) return false;
    std::string current;
    size_t pos = 0;
    while (pos <= text.size()) {
        const size_t end = text.find('\n', pos);
        std::string line =
                text.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
        line = trim(line);
        if (!line.empty() && line[0] != '#') {
            if (line[0] == '@') {
                current = trim(line.substr(1));
                if (!current.empty()) g_spoof_apps[current];
            } else if (!current.empty()) {
                const auto eq = line.find('=');
                if (eq != std::string::npos) {
                    const std::string key = trim(line.substr(0, eq));
                    const std::string value = trim(line.substr(eq + 1));
                    if (!key.empty()) g_spoof_apps[current][key] = value;
                }
            }
        }
        if (end == std::string::npos) break;
        pos = end + 1;
    }
    return !g_spoof_apps.empty();
}

// `/proc/self/cmdline` is the process name, e.g. `com.example.app` or
// `com.example.app:remote`. Strip the sub-process suffix for matching.
std::string app_package(const std::string& name) {
    const auto colon = name.find(':');
    return colon == std::string::npos ? name : name.substr(0, colon);
}

std::string read_cmdline() {
    std::string value;
    if (!read_file("/proc/self/cmdline", value, 512)) return {};
    const auto nul = value.find('\0');
    if (nul != std::string::npos) value.erase(nul);
    return value;
}

void set_static_string(JNIEnv* env, jclass clazz, const char* name, const std::string& value) {
    jfieldID field = env->GetStaticFieldID(clazz, name, "Ljava/lang/String;");
    if (field == nullptr) {
        env->ExceptionClear();
        return;
    }
    jstring string = env->NewStringUTF(value.c_str());
    env->SetStaticObjectField(clazz, field, string);
    env->DeleteLocalRef(string);
}

void set_static_int(JNIEnv* env, jclass clazz, const char* name, int value) {
    jfieldID field = env->GetStaticFieldID(clazz, name, "I");
    if (field == nullptr) {
        env->ExceptionClear();
        return;
    }
    env->SetStaticIntField(clazz, field, value);
}

// Mirror the matching `ro.*` overrides onto the android.os.Build fields the
// app reads directly. Property reads are interposed separately below; this
// covers the static fields that were captured before the overrides existed.
void spoof_build_overrides(JNIEnv* env, const PropMap& props) {
    auto value = [&](const char* key) -> const std::string* {
        const auto it = props.find(key);
        return it == props.end() ? nullptr : &it->second;
    };
    jclass build = env->FindClass("android/os/Build");
    if (build == nullptr) {
        env->ExceptionClear();
        return;
    }
    auto set_build = [&](const char* field, const char* key) {
        if (const auto* v = value(key)) set_static_string(env, build, field, *v);
    };
    set_build("MANUFACTURER", "ro.product.manufacturer");
    set_build("BRAND", "ro.product.brand");
    set_build("MODEL", "ro.product.model");
    set_build("PRODUCT", "ro.product.name");
    set_build("DEVICE", "ro.product.device");
    set_build("BOARD", "ro.product.board");
    set_build("HARDWARE", "ro.hardware");
    set_build("DISPLAY", "ro.build.display.id");
    set_build("FINGERPRINT", "ro.build.fingerprint");
    set_build("ID", "ro.build.id");
    set_build("INCREMENTAL", "ro.build.version.incremental");
    set_build("TYPE", "ro.build.type");
    set_build("TAGS", "ro.build.tags");
    env->DeleteLocalRef(build);

    jclass version = env->FindClass("android/os/Build$VERSION");
    if (version == nullptr) {
        env->ExceptionClear();
        return;
    }
    auto set_version = [&](const char* field, const char* key) {
        if (const auto* v = value(key)) set_static_string(env, version, field, *v);
    };
    set_version("RELEASE", "ro.build.version.release");
    set_version("SECURITY_PATCH", "ro.build.version.security_patch");
    set_version("INCREMENTAL", "ro.build.version.incremental");
    if (const auto* v = value("ro.product.first_api_level")) {
        char* endptr = nullptr;
        const long sdk = strtol(v->c_str(), &endptr, 10);
        if (endptr != nullptr && *endptr == '\0') {
            set_static_int(env, version, "DEVICE_INITIAL_SDK_INT", static_cast<int>(sdk));
        }
    } else if (const auto* v = value("ro.board.first_api_level")) {
        char* endptr = nullptr;
        const long sdk = strtol(v->c_str(), &endptr, 10);
        if (endptr != nullptr && *endptr == '\0') {
            set_static_int(env, version, "DEVICE_INITIAL_SDK_INT", static_cast<int>(sdk));
        }
    }
    env->DeleteLocalRef(version);
}

struct PropInfoLayout {
    uint32_t serial;
    char value[PROP_VALUE_MAX];
    char name[1];
};

const char* spoof_property(const char* name) {
    if (g_overrides == nullptr) return nullptr;
    const auto it = g_overrides->find(name);
    return it == g_overrides->end() ? nullptr : it->second.c_str();
}

// ProcessState::self() returns sp<ProcessState> by value. AAPCS64 returns a
// type with a non-trivial destructor through the caller-provided buffer in x8,
// not in x0. Declaring the function as `void* (*)()` leaves x8 uninitialized,
// so libbinder writes the sp through a garbage address and every app process
// crashes. This mirror type has the same single-pointer layout and a
// non-trivial destructor, which makes the compiler pass the hidden buffer the
// same way it does for sp<ProcessState>.
struct ProcessStateSp {
    void* ptr;
    ProcessStateSp() : ptr(nullptr) {}
    ProcessStateSp(const ProcessStateSp&) = delete;
    ProcessStateSp& operator=(const ProcessStateSp&) = delete;
    ~ProcessStateSp() {}
};

// The zygote's nativeZygoteInit normally starts the binder thread pool; the
// replacement has to keep doing that or the app process cannot talk to
// system_server.
void start_binder_pool() {
    using SelfFn = ProcessStateSp (*)();
    using StartFn = void (*)(void*);
    SelfFn self = reinterpret_cast<SelfFn>(
            dlsym(RTLD_DEFAULT, "_ZN7android12ProcessState4selfEv"));
    StartFn start = reinterpret_cast<StartFn>(
            dlsym(RTLD_DEFAULT, "_ZN7android12ProcessState15startThreadPoolEv"));
    if (self == nullptr || start == nullptr) {
        void* binder = dlopen("libbinder.so", RTLD_NOW);
        if (binder != nullptr) {
            self = reinterpret_cast<SelfFn>(
                    dlsym(binder, "_ZN7android12ProcessState4selfEv"));
            start = reinterpret_cast<StartFn>(
                    dlsym(binder, "_ZN7android12ProcessState15startThreadPoolEv"));
        }
    }
    if (self != nullptr && start != nullptr) {
        ProcessStateSp state = self();
        if (state.ptr != nullptr) start(state.ptr);
    } else {
        LOGE("ProcessState::startThreadPool unavailable");
    }
}

void spoof_native_zygote_init(JNIEnv* env, jclass) {
    const std::string name = read_cmdline();
    const auto spoof = g_spoof_apps.find(app_package(name));
    if (spoof != g_spoof_apps.end()) {
        g_overrides = &spoof->second;
        spoof_build_overrides(env, spoof->second);
        LOGI("spoofed %s: %zu props", name.c_str(), spoof->second.size());
    }
    start_binder_pool();
}

// Resolve the next definition of a symbol. A preloaded library defines
// unversioned symbols, while platform callers may reference LIBC/LIBC_O
// versions; bionic accepts the unversioned definition. RTLD_DEFAULT and a
// no-load dlopen are fallbacks for the case where RTLD_NEXT does not see the
// provider in the caller's lookup scope.
void* resolve_real(const char* symbol, const char* library) {
    void* resolved = dlsym(RTLD_NEXT, symbol);
    if (resolved == nullptr) resolved = dlsym(RTLD_DEFAULT, symbol);
    if (resolved == nullptr && library != nullptr) {
        void* handle = dlopen(library, RTLD_NOW | RTLD_NOLOAD);
        if (handle != nullptr) resolved = dlsym(handle, symbol);
    }
    return resolved;
}

// Read through the real libc getter; calling our own interposed symbol would
// recurse.
int raw_property_get(const char* name, char* value) {
    using RealFn = int (*)(const char*, char*);
    static RealFn real = reinterpret_cast<RealFn>(
            resolve_real("__system_property_get", "libc.so"));
    if (real == nullptr) {
        if (value != nullptr) value[0] = '\0';
        return 0;
    }
    return real(name, value);
}

// The alternate (hidden) edition is picked at boot from
// /mnt/vendor/persist/customize, which is factory data. Rather than rewriting
// that file, let the developer-options "device compatibility test mode"
// toggle drive the edition for every reader: while
// persist.sys.config.model_cust is "1", reads of the factory customize token
// answer "MINGCHAO". Any other value (including unset) returns the real
// factory value, so turning the toggle off restores the factory edition.
bool edition_active(const char* name) {
    if (name == nullptr || strcmp(name, kEditionProp) != 0) {
        return false;
    }
    char value[PROP_VALUE_MAX] = {};
    return raw_property_get(kEditionSwitch, value) == 1 && value[0] == '1';
}

const char* edition_alias(const char* name) {
    return edition_active(name) ? kEditionAlias : nullptr;
}

// A stand-in `prop_info` for the edition token. No prop file defines that
// name on this platform, and Android's SystemProperties.get resolves a key
// with `__system_property_find` *before* it ever reads a value: a null lookup
// returns the caller's default without invoking
// `__system_property_read_callback`. Interposing only the read path therefore
// never fires for a property that does not exist, so `find` has to report it.
// The layout mirrors bionic's `prop_info` (`PropInfoLayout` above), which keeps
// the returned pointer safe for callers that read the serial or value inline.
struct EditionPropInfo {
    uint32_t serial;
    char value[PROP_VALUE_MAX];
    char name[sizeof(kEditionProp)];
};

const EditionPropInfo& edition_prop_info() {
    // Serial value bits: bit 0 means "being updated", bit 1 marks a long
    // property; keep both clear so the record looks like a settled short one.
    static const EditionPropInfo info = [] {
        EditionPropInfo prop = {};
        prop.serial = 4;
        std::strncpy(prop.value, kEditionAlias, sizeof(prop.value) - 1);
        std::strncpy(prop.name, kEditionProp, sizeof(prop.name) - 1);
        return prop;
    }();
    return info;
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void
_ZN7android14AndroidRuntime8startRegEP7_JNIEnv(JNIEnv* env) {
    using StartRegFn = void (*)(JNIEnv*);
    static StartRegFn real = reinterpret_cast<StartRegFn>(
            resolve_real(kStartRegSymbol, "libandroid_runtime.so"));
    if (real == nullptr) {
        // Returning here would skip the real startReg and leave the runtime
        // without its JNI registrations, which fails later and less clearly.
        LOGE("startReg original not found; aborting");
        abort();
    }
    real(env);
    load_spoof_config();

    // A process launched through the `wrap.<package>` property runs
    // WrapperInit instead of ZygoteConnection, so ZygoteInit.nativeZygoteInit
    // is never called and the per-app overrides above would never apply.
    // The cmdline is the package name for that path, so apply them here too.
    {
        const std::string name = read_cmdline();
        const auto spoof = g_spoof_apps.find(app_package(name));
        if (spoof != g_spoof_apps.end()) {
            g_overrides = &spoof->second;
            spoof_build_overrides(env, spoof->second);
            LOGI("spoofed (startReg) %s: %zu props", name.c_str(), spoof->second.size());
        }
    }

    jclass zygote = env->FindClass("com/android/internal/os/ZygoteInit");
    if (zygote == nullptr) {
        env->ExceptionClear();
        return;
    }
    JNINativeMethod method = {
            const_cast<char*>("nativeZygoteInit"),
            const_cast<char*>("()V"),
            reinterpret_cast<void*>(spoof_native_zygote_init),
    };
    if (env->RegisterNatives(zygote, &method, 1) != JNI_OK) {
        env->ExceptionClear();
        LOGE("RegisterNatives(nativeZygoteInit) failed");
    }
    env->DeleteLocalRef(zygote);
}

extern "C" __attribute__((visibility("default"))) const prop_info*
__system_property_find(const char* name) {
    using RealFn = const prop_info* (*)(const char*);
    static RealFn real = reinterpret_cast<RealFn>(
            resolve_real("__system_property_find", "libc.so"));
    // Report the edition token even though no prop file defines it; the
    // aliased value itself comes from __system_property_read_callback below.
    if (edition_active(name)) {
        return reinterpret_cast<const prop_info*>(&edition_prop_info());
    }
    if (real == nullptr) {
        LOGE("__system_property_find original not found");
        return nullptr;
    }
    return real(name);
}

extern "C" __attribute__((visibility("default"))) int
__system_property_get(const char* name, char* value) {
    using RealFn = int (*)(const char*, char*);
    static RealFn real = reinterpret_cast<RealFn>(
            resolve_real("__system_property_get", "libc.so"));
    const char* spoofed = edition_alias(name);
    if (spoofed == nullptr) spoofed = spoof_property(name);
    if (spoofed != nullptr) {
        size_t length = strlen(spoofed);
        if (length >= PROP_VALUE_MAX) length = PROP_VALUE_MAX - 1;
        memcpy(value, spoofed, length);
        value[length] = '\0';
        return static_cast<int>(length);
    }
    if (real == nullptr) {
        LOGE("__system_property_get original not found");
        return 0;
    }
    return real(name, value);
}

extern "C" __attribute__((visibility("default"))) void
__system_property_read_callback(
        const prop_info* info,
        void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial),
        void* cookie) {
    using RealFn = void (*)(const prop_info*,
                            void (*)(void*, const char*, const char*, uint32_t),
                            void*);
    static RealFn real = reinterpret_cast<RealFn>(
            resolve_real("__system_property_read_callback", "libc.so"));
    if (info != nullptr && callback != nullptr) {
        const auto* layout = reinterpret_cast<const PropInfoLayout*>(info);
        const char* alias = edition_alias(layout->name);
        if (alias != nullptr) {
            callback(cookie, layout->name, alias, layout->serial);
            return;
        }
        const char* spoofed = spoof_property(layout->name);
        if (spoofed != nullptr) {
            callback(cookie, layout->name, spoofed, layout->serial);
            return;
        }
    }
    if (real == nullptr) {
        LOGE("__system_property_read_callback original not found");
        return;
    }
    real(info, callback, cookie);
}
