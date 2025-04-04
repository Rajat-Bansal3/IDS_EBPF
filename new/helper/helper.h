#ifndef HELPER_H
#define HELPER_H

#define MAX_PATH_LEN 256

void normalize_path(const char *input, char *output);
u32 bpf_hash_str(const char *str);
u64 bpf_hash_path(const char *path);
const char *get_basename(const char *path);

#endif

