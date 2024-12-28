#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>
#include <emmintrin.h>

#define ERR_KEY_LEN_NOT_EQUAL_DATA_LEN -1

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len);

int16_t sse_xor_encrypt(const uint8_t* key, const size_t key_len, const uint8_t* data, const size_t data_len, uint8_t* out)
{
    if(key_len < data_len)
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

int main()
{
	uint8_t public_key[OQS_KEM_frodokem_1344_aes_length_public_key];
	uint8_t secret_key[OQS_KEM_frodokem_1344_aes_length_secret_key];
	uint8_t ciphertext[OQS_KEM_frodokem_1344_aes_length_ciphertext];
	uint8_t shared_secret_e[OQS_KEM_frodokem_1344_aes_length_shared_secret];
	uint8_t shared_secret_d[OQS_KEM_frodokem_1344_aes_length_shared_secret];
    const char* src_string = "hello world!\n";
    size_t src_string_len = strlen(src_string);
    char enc_string[512] = {0};

	OQS_STATUS rc = OQS_KEM_frodokem_1344_aes_keypair(public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_frodokem_1344_aes_keypair failed!\n");
		cleanup_stack(secret_key, OQS_KEM_frodokem_1344_aes_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_frodokem_1344_aes_length_shared_secret);

		return OQS_ERROR;
	}
	rc = OQS_KEM_frodokem_1344_aes_encaps(ciphertext, shared_secret_e, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_frodokem_1344_aes_encaps failed!\n");
		cleanup_stack(secret_key, OQS_KEM_frodokem_1344_aes_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_frodokem_1344_aes_length_shared_secret);

		return OQS_ERROR;
	}

    sse_xor_encrypt((const uint8_t*)shared_secret_e, OQS_KEM_frodokem_1344_aes_length_shared_secret, (const uint8_t*)src_string, src_string_len, (uint8_t*)enc_string);


	rc = OQS_KEM_frodokem_1344_aes_decaps(shared_secret_d, ciphertext, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_frodokem_1344_aes_decaps failed!\n");
		cleanup_stack(secret_key, OQS_KEM_frodokem_1344_aes_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_frodokem_1344_aes_length_shared_secret);

		return OQS_ERROR;
	}
    
    {
        char dec_string[512];
        sse_xor_encrypt((const uint8_t*)shared_secret_d, OQS_KEM_frodokem_1344_aes_length_shared_secret, (const uint8_t*)enc_string, src_string_len, (uint8_t*)dec_string);
        puts(dec_string);
    }

	printf("[example_stack] OQS_KEM_frodokem_1344_aes operations completed.\n");

	return OQS_SUCCESS; // success!
}

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
	OQS_MEM_cleanse(shared_secret_e, shared_secret_len);
	OQS_MEM_cleanse(shared_secret_d, shared_secret_len);
}
