#include "wrapper.hpp"
#include "vmaware.hpp"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>

namespace {

char* copy_string(const std::string& value) {
    char* out = static_cast<char*>(std::malloc(value.size() + 1));
    if (out == nullptr) return nullptr;
    std::memcpy(out, value.c_str(), value.size() + 1);
    return out;
}

} // namespace

extern "C" {

bool vmaware_detect(bool* out, char** err) {
    try {
        *out = VM::detect();
        *err = nullptr;
        return true;
    } catch (const std::exception& e) {
        *err = copy_string(e.what());
        return false;
    } catch (...) {
        *err = copy_string("unknown C++ exception");
        return false;
    }
}

bool vmaware_check(unsigned char flag, bool* out, char** err) {
    try {
        *out = VM::check(static_cast<VM::enum_flags>(flag));
        *err = nullptr;
        return true;
    } catch (const std::exception& e) {
        *err = copy_string(e.what());
        return false;
    } catch (...) {
        *err = copy_string("unknown C++ exception");
        return false;
    }
}

bool vmaware_type(char** out, char** err) {
    try {
        *out = copy_string(VM::type());
        *err = nullptr;
        return true;
    } catch (const std::exception& e) {
        *err = copy_string(e.what());
        return false;
    } catch (...) {
        *err = copy_string("unknown C++ exception");
        return false;
    }
}

bool vmaware_percentage(uint8_t* out, char** err) {
    try {
        *out = VM::percentage();
        *err = nullptr;
        return true;
    } catch (const std::exception& e) { *err = copy_string(e.what()); return false; }
    catch (...) { *err = copy_string("unknown C++ exception"); return false; }
}

bool vmaware_conclusion(char** out, char** err) {
    try {
        *out = copy_string(VM::conclusion());
        *err = nullptr;
        return true;
    } catch (const std::exception& e) { *err = copy_string(e.what()); return false; }
    catch (...) { *err = copy_string("unknown C++ exception"); return false; }
}

bool vmaware_detected_count(uint8_t* out, char** err) {
    try {
        *out = VM::detected_count();
        *err = nullptr;
        return true;
    } catch (const std::exception& e) { *err = copy_string(e.what()); return false; }
    catch (...) { *err = copy_string("unknown C++ exception"); return false; }
}

bool vmaware_is_hardened(bool* out, char** err) {
    try {
        *out = VM::is_hardened();
        *err = nullptr;
        return true;
    } catch (const std::exception& e) { *err = copy_string(e.what()); return false; }
    catch (...) { *err = copy_string("unknown C++ exception"); return false; }
}

bool vmaware_brand(char** out, char** err) {
    try {
        *out = copy_string(VM::brand());
        *err = nullptr;
        return true;
    } catch (const std::exception& e) {
        *err = copy_string(e.what());
        return false;
    } catch (...) {
        *err = copy_string("unknown C++ exception");
        return false;
    }
}

void free_string(char* value) {
    std::free(value);
}

} // extern "C"