// Restricted native shared-library loading for the Veloce agent.
#pragma once

#include <filesystem>
#include <string>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace veloce::platform {

class SharedLibrary {
public:
    SharedLibrary() = default;
    ~SharedLibrary() { close(); }
    SharedLibrary(const SharedLibrary&) = delete;
    SharedLibrary& operator=(const SharedLibrary&) = delete;

    bool open(const std::string& path, std::string& error) {
        close();
        std::filesystem::path native(path);
        if (!native.is_absolute()) {
            error = "shared library path must be absolute";
            return false;
        }
#ifdef _WIN32
        // Search only the requested DLL's directory and System32. The agent
        // never falls back to the process working directory or PATH.
        handle_ = LoadLibraryExW(
            native.wstring().c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!handle_) {
            error = "LoadLibraryExW failed (" +
                    std::to_string(GetLastError()) + ")";
            return false;
        }
#else
        handle_ = dlopen(native.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!handle_) {
            const char* detail = dlerror();
            error = std::string("dlopen failed: ") +
                    (detail ? detail : "unknown error");
            return false;
        }
#endif
        return true;
    }

    void* symbol(const char* name) const {
#ifdef _WIN32
        return handle_ ? reinterpret_cast<void*>(GetProcAddress(handle_, name))
                       : nullptr;
#else
        return handle_ ? dlsym(handle_, name) : nullptr;
#endif
    }

    void close() {
#ifdef _WIN32
        if (handle_) FreeLibrary(handle_);
#else
        if (handle_) dlclose(handle_);
#endif
        handle_ = nullptr;
    }

private:
#ifdef _WIN32
    HMODULE handle_ = nullptr;
#else
    void* handle_ = nullptr;
#endif
};

} // namespace veloce::platform
