#include <cstdint>
extern "C" {
bool vmaware_detect(bool *out, char **err);
bool vmaware_type(char **out, char **err);
bool vmaware_check(unsigned char flag, bool *out, char **err);
bool vmaware_percentage(uint8_t *out, char **err);
bool vmaware_conclusion(char **out, char **err);
bool vmaware_detected_count(uint8_t *out, char **err);
bool vmaware_is_hardened(bool *out, char **err);
bool vmaware_brand(char** out, char** err);
void free_string(char *s);
}