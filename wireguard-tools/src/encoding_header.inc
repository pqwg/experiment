#define WG_KEY_LEN_BASE64 ((((WG_KEY_LEN) + 2) / 3) * 4 + 1)
#define WG_KEY_LEN_HEX (WG_KEY_LEN * 2 + 1)

void ENCODING_FUNCTION(key_to_base64)(char base64[static WG_KEY_LEN_BASE64], const uint8_t key[static WG_KEY_LEN]);
bool ENCODING_FUNCTION(key_from_base64)(uint8_t key[static WG_KEY_LEN], const char *base64);

void ENCODING_FUNCTION(key_to_hex)(char hex[static WG_KEY_LEN_HEX], const uint8_t key[static WG_KEY_LEN]);
bool ENCODING_FUNCTION(key_from_hex)(uint8_t key[static WG_KEY_LEN], const char *hex);

bool ENCODING_FUNCTION(key_is_zero)(const uint8_t key[static WG_KEY_LEN]);

#undef ENCODING_FUNCTION
#undef WG_KEY_LEN
#undef WG_KEY_LEN_HEX
#undef WG_KEY_LEN_BASE64