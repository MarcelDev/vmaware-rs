// C ABI wrappers around the VMAware C++ header.

#include "vmaware.hpp"

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>

namespace {

char* copy_string(const std::string& value) {
    const std::size_t len = value.size();
    char* out = static_cast<char*>(std::malloc(len + 1));

    if (out == nullptr) {
        return nullptr;
    }

    std::memcpy(out, value.c_str(), len + 1);
    return out;
}

char* current_exception_message() {
    try {
        throw;
    } catch (const std::exception& error) {
        return copy_string(error.what());
    } catch (...) {
        return copy_string("unknown C++ exception");
    }
}

template <typename Fn, typename T>
bool write_result(T* out, char** error, Fn&& fn) {
    if (out == nullptr) {
        if (error != nullptr) {
            *error = copy_string("null output pointer");
        }
        return false;
    }

    try {
        *out = fn();
        if (error != nullptr) {
            *error = nullptr;
        }
        return true;
    } catch (...) {
        if (error != nullptr) {
            *error = current_exception_message();
        }
        return false;
    }
}

VM::flagset make_flags(const unsigned char* flags, std::size_t len) {
    VM::flagset out;

    if (len == 0) {
        VM::core::generate_default(out);
        return out;
    }

    for (std::size_t i = 0; i < len; ++i) {
        out.set(static_cast<std::size_t>(flags[i]), true);
    }

    if (out.test(VM::DEFAULT)) {
        VM::core::generate_default(out);
    }

    if (VM::core::are_techniques_empty(out)) {
        out |= VM::core::generate_default();
    }

    if (out.test(VM::ALL)) {
        VM::core::generate_all(out);
    }

    for (unsigned char i = 0; i < VM::enum_size + 1; ++i) {
        if (VM::core::disabled_flag_collector.test(i)) {
            out.set(i, false);
        }
    }

    return out;
}

} // namespace

extern "C" {

bool vmaware_try_check(unsigned char flag, bool* out, char** error) {
    return write_result(out, error, [&]() {
        return VM::check(static_cast<VM::enum_flags>(flag));
    });
}

bool vmaware_try_detect(bool* out, char** error) {
    return write_result(out, error, []() {
        return VM::detect();
    });
}

bool vmaware_try_detect_with(const unsigned char* flags, std::size_t len, bool* out, char** error) {
    return write_result(out, error, [&]() {
        return VM::detect(make_flags(flags, len));
    });
}

bool vmaware_try_percentage(unsigned char* out, char** error) {
    return write_result(out, error, []() {
        return VM::percentage();
    });
}

bool vmaware_try_percentage_with(const unsigned char* flags, std::size_t len, unsigned char* out, char** error) {
    return write_result(out, error, [&]() {
        return VM::percentage(make_flags(flags, len));
    });
}

bool vmaware_try_detected_count(unsigned char* out, char** error) {
    return write_result(out, error, []() {
        return VM::detected_count();
    });
}

bool vmaware_try_detected_count_with(const unsigned char* flags, std::size_t len, unsigned char* out, char** error) {
    return write_result(out, error, [&]() {
        return VM::detected_count(make_flags(flags, len));
    });
}

unsigned short vmaware_technique_count() {
    return VM::technique_count;
}

bool vmaware_try_is_hardened(bool* out, char** error) {
    return write_result(out, error, []() {
        return VM::is_hardened();
    });
}

bool vmaware_try_brand(char** out, char** error) {
    return write_result(out, error, []() {
        return copy_string(VM::brand());
    });
}

bool vmaware_try_brand_with(const unsigned char* flags, std::size_t len, char** out, char** error) {
    return write_result(out, error, [&]() {
        return copy_string(VM::brand(make_flags(flags, len)));
    });
}

bool vmaware_try_type(char** out, char** error) {
    return write_result(out, error, []() {
        return copy_string(VM::type());
    });
}

bool vmaware_try_type_with(const unsigned char* flags, std::size_t len, char** out, char** error) {
    return write_result(out, error, [&]() {
        return copy_string(VM::type(make_flags(flags, len)));
    });
}

bool vmaware_try_conclusion(char** out, char** error) {
    return write_result(out, error, []() {
        return copy_string(VM::conclusion());
    });
}

bool vmaware_try_conclusion_with(const unsigned char* flags, std::size_t len, char** out, char** error) {
    return write_result(out, error, [&]() {
        return copy_string(VM::conclusion(make_flags(flags, len)));
    });
}

bool vmaware_try_flag_to_string(unsigned char flag, char** out, char** error) {
    return write_result(out, error, [&]() {
        return copy_string(VM::flag_to_string(static_cast<VM::enum_flags>(flag)));
    });
}

void vmaware_string_free(char* value) {
    std::free(value);
}

} // extern "C"
