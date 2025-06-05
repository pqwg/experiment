#define WG_KEY_LEN_BASE64 ((((WG_KEY_LEN) + 2) / 3) * 4 + 1)
#define WG_KEY_LEN_HEX (WG_KEY_LEN * 2 + 1)

void ENCODING_FUNCTION(key_to_base64)(char base64[static WG_KEY_LEN_BASE64], const uint8_t key[static WG_KEY_LEN])
{
	// unsigned int i;

	// for (i = 0; i < WG_KEY_LEN / 3; ++i)
	// 	encode_base64(&base64[i * 4], &key[i * 3]);
	// encode_base64(&base64[i * 4], (const uint8_t[]){ key[i * 3 + 0], key[i * 3 + 1], 0 });
	// base64[WG_KEY_LEN_BASE64 - 2] = '=';
	// base64[WG_KEY_LEN_BASE64 - 1] = '\0';
	base64_encode(key, WG_KEY_LEN, base64);
	base64[WG_KEY_LEN_BASE64-1] = '\0';
}

bool ENCODING_FUNCTION(key_from_base64)(uint8_t key[static WG_KEY_LEN], const char *base64)
{
	int len = base64_decode(base64, WG_KEY_LEN_BASE64 - 1, key);
	return (len == WG_KEY_LEN);
	// unsigned int i;
	// volatile uint8_t ret = 0;
	// int val;

	// if (strlen(base64) != WG_KEY_LEN_BASE64 - 1 || base64[WG_KEY_LEN_BASE64 - 2] != '=')
	// 	return false;

	// for (i = 0; i < WG_KEY_LEN / 3; ++i) {
	// 	val = decode_base64(&base64[i * 4]);
	// 	ret |= (uint32_t)val >> 31;
	// 	key[i * 3 + 0] = (val >> 16) & 0xff;
	// 	key[i * 3 + 1] = (val >> 8) & 0xff;
	// 	key[i * 3 + 2] = val & 0xff;
	// }
	// val = decode_base64((const char[]){ base64[i * 4 + 0], base64[i * 4 + 1], base64[i * 4 + 2], 'A' });
	// ret |= ((uint32_t)val >> 31) | (val & 0xff);
	// key[i * 3 + 0] = (val >> 16) & 0xff;
	// key[i * 3 + 1] = (val >> 8) & 0xff;
}

void ENCODING_FUNCTION(key_to_hex)(char hex[static WG_KEY_LEN_HEX], const uint8_t key[static WG_KEY_LEN])
{
	unsigned int i;

	for (i = 0; i < WG_KEY_LEN; ++i) {
		hex[i * 2] = 87U + (key[i] >> 4) + ((((key[i] >> 4) - 10U) >> 8) & ~38U);
		hex[i * 2 + 1] = 87U + (key[i] & 0xf) + ((((key[i] & 0xf) - 10U) >> 8) & ~38U);
	}
	hex[i * 2] = '\0';
}

bool ENCODING_FUNCTION(key_from_hex)(uint8_t key[static WG_KEY_LEN], const char *hex)
{
	uint8_t c, c_acc, c_alpha0, c_alpha, c_num0, c_num, c_val;
	volatile uint8_t ret = 0;

	if (strlen(hex) != WG_KEY_LEN_HEX - 1)
		return false;

	for (unsigned int i = 0; i < WG_KEY_LEN_HEX - 1; i += 2) {
		c = (uint8_t)hex[i];
		c_num = c ^ 48U;
		c_num0 = (c_num - 10U) >> 8;
		c_alpha = (c & ~32U) - 55U;
		c_alpha0 = ((c_alpha - 10U) ^ (c_alpha - 16U)) >> 8;
		ret |= ((c_num0 | c_alpha0) - 1) >> 8;
		c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);
		c_acc = c_val * 16U;

		c = (uint8_t)hex[i + 1];
		c_num = c ^ 48U;
		c_num0 = (c_num - 10U) >> 8;
		c_alpha = (c & ~32U) - 55U;
		c_alpha0 = ((c_alpha - 10U) ^ (c_alpha - 16U)) >> 8;
		ret |= ((c_num0 | c_alpha0) - 1) >> 8;
		c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);
		key[i / 2] = c_acc | c_val;
	}

	return 1 & ((ret - 1) >> 8);
}

bool ENCODING_FUNCTION(key_is_zero)(const uint8_t key[static WG_KEY_LEN])
{
	volatile uint8_t acc = 0;

	for (unsigned int i = 0; i < WG_KEY_LEN; ++i) {
		acc |= key[i];
		asm volatile("" : "=r"(acc) : "0"(acc));
	}
	return 1 & ((acc - 1) >> 8);
}

#undef WG_KEY_LEN_BASE64
#undef WG_KEY_LEN_HEX
#undef ENCODING_FUNCTION
#undef WG_KEY_LEN