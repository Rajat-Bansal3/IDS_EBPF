#include <helper.h>

static __always_inline void normalize_path(const char *input, char *output) {
    char temp[MAX_PATH_LEN] = {0};
    int i = 0, j = 0;
    bool trailing_slash = false;

    
    if (input[0] == '/') {
        temp[j++] = '/';
        i++;
    }

    while (input[i] != '\0' && j < MAX_PATH_LEN - 1) {
        
        if (input[i] == '/' && (j > 0 && temp[j-1] == '/')) {
            i++;
            continue;
        }

        
        if (input[i] == '.' && (input[i+1] == '/' || input[i+1] == '\0')) {
            i += (input[i+1] == '/') ? 2 : 1;
            continue;
        }

        
        if (input[i] == '.' && input[i+1] == '.' && 
            (input[i+2] == '/' || input[i+2] == '\0')) {
            
            
            if (j > 1) {
                j--; 
                while (j > 0 && temp[j-1] != '/') {
                    j--;
                }
                
                if (j == 0 && temp[0] == '/') j = 1;
            }
            i += (input[i+2] == '/') ? 3 : 2;
            continue;
        }

        
        temp[j++] = input[i++];
        trailing_slash = (temp[j-1] == '/');
    }

    
    if (j > 1 && trailing_slash) {
        j--;
    }

    
    temp[j] = '\0';
    bpf_probe_read_kernel_str(output, MAX_PATH_LEN, temp);
}



static __always_inline u32 bpf_hash_str(const char *str) {
    u32 hash = 0;
    #pragma clang loop unroll(full)
    for (int i = 0; str[i] != '\0' && i < 64; i++) {
        hash += str[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    return hash;
}


static __always_inline u64 bpf_hash_path(const char *path) {
    char normalized[128];
    normalize_path(path, normalized);  
    return bpf_hash_str(normalized);
}

