#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <emmintrin.h>

#define ERR_KEY_LEN_NOT_EQUAL_DATA_LEN -1

int16_t sse_xor_encrypt(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t* out)
{
    if (key_len < data_len)
    {
        return ERR_KEY_LEN_NOT_EQUAL_DATA_LEN;
    }

    size_t i = 0;
    if (data_len >= 16)
    {
        for (; i + 16 <= data_len; i += 16)
        {
            __m128i vec_key = _mm_loadu_si128((const __m128i*)(key + i));
            __m128i vec_data = _mm_loadu_si128((const __m128i*)(data + i));

            __m128i vec_res = _mm_xor_si128(vec_key, vec_data);

            _mm_storeu_si128((__m128i*)(out + i), vec_res);
        }
    }

    for (; i < data_len; ++i)
    {
        out[i] = key[i] ^ data[i];
    }

    return 0;
}

int main(int argc, char* argv[])
{
    if (argc == 3)
    {
        FILE* file = fopen(argv[2], "rb+");
        if (file == NULL)
        {
            printf("failed to open file %s", argv[2]);
            return -1;
        }

        FILE* key_file = fopen(argv[1], "rb+");
        if (file == NULL)
        {
            printf("failed to open file %s", argv[1]);
            return -1;
        }

        fseek(file, 0L, SEEK_END);
        size_t fsize = ftell(file);
        fseek(file, 0L, SEEK_SET);
        fseek(key_file, 0L, SEEK_END);
        size_t kfsize = ftell(key_file);
        fseek(key_file, 0L, SEEK_SET);

        uint8_t* out_data = (uint8_t*)malloc(fsize + 1);
        uint8_t* file_data = (uint8_t*)malloc(fsize + 1);
        uint8_t* key_data = (uint8_t*)malloc(kfsize + 1);
        fread(file_data, sizeof(uint8_t), fsize, file);
        fread(key_data, sizeof(uint8_t), kfsize, key_file);
        fclose(file);
        fclose(key_file);

        int16_t res = sse_xor_encrypt(key_data, kfsize, file_data, fsize, out_data);
        if (res == ERR_KEY_LEN_NOT_EQUAL_DATA_LEN)
        {
            free(out_data);
            free(file_data);
            free(key_data);
            puts("error: ERR_KEY_LEN_NOT_EQUAL_DATA_LEN");
            return -1;
        }

        fopen(argv[2], "wb");
        fwrite(out_data, sizeof(char), fsize, file);
        free(out_data);
        free(file_data);
        free(key_data);
    }
    else
    {
        puts("<key_filename> <filename>");
        return -1;
    }

    return 0;
}