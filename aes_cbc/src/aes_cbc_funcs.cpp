#define EXTENSION_NAME aes_cbc
#define LIB_NAME "aes_cbc"
#define MODULE_NAME "aes_cbc"

#include <dmsdk/sdk.h>
#include <vector>
#include <cstdlib> 
#include <ctime>   
#include <cstdint>
#include <cmath>

#include "aes.h"

#include <dmsdk/dlib/crypt.h>

static void secure_wipe(void* ptr, size_t size) 
{
	volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
	while (size--) {
		*p++ = 0;
	}
}

static void generate_random_iv(std::vector<uint8_t>& iv) {
	iv.resize(16);

	// static counter ensures that even if called multiple times in the same second, the IV seed will be different,
	static unsigned int seed_counter = 0;
	if (seed_counter == 0) {
		srand((unsigned int)time(NULL));
	}
	seed_counter++;

	for (int i = 0; i < 16; ++i) {
		// mix rand() with the counter to ensure strict uniqueness
		iv[i] = (uint8_t)((rand() + seed_counter + i) % 256);
	}
}

static int encrypt_newgrounds(lua_State* L) {
	size_t data_len;
	const char* data = luaL_checklstring(L, 1, &data_len);
	if (data_len == 0) return luaL_error(L, "Data cannot be empty.");

	size_t b64_key_len;
	const char* b64_key = luaL_checklstring(L, 2, &b64_key_len);

	// decode the Newgrounds Base64 key into raw bytes
	uint32_t key_max_len = (b64_key_len / 4) * 3;
	std::vector<uint8_t> key(key_max_len);
	uint32_t decoded_key_len = key_max_len;

	if (!dmCrypt::Base64Decode((const uint8_t*)b64_key, b64_key_len, key.data(), &decoded_key_len)) {
		return luaL_error(L, "Failed to decode Newgrounds Base64 key.");
	}
	key.resize(decoded_key_len); 

	// generate a random 16-byte IV
	std::vector<uint8_t> iv;
	generate_random_iv(iv); 
	const size_t iv_size = 16;

	// calculate PKCS#7 Padding
	// CBC requires the payload length to be an exact multiple of 16 bytes.
	size_t pad_len = 16 - (data_len % 16);
	size_t padded_data_len = data_len + pad_len;
	uint8_t pad_val = static_cast<uint8_t>(pad_len);

	// prepare Blob [IV + cipher data]
	std::vector<uint8_t> blob(iv_size + padded_data_len);
	std::memcpy(blob.data(), iv.data(), iv_size);
	std::memcpy(blob.data() + iv_size, data, data_len);

	// apply the padding bytes to the end of the data block
	for (size_t i = 0; i < pad_len; ++i) {
		blob[iv_size + data_len + i] = pad_val;
	}

	// encrypt data portion using CBC Mode
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key.data(), iv.data());

	// Using CBC instead of CTR
	AES_CBC_encrypt_buffer(&ctx, blob.data() + iv_size, padded_data_len);

	// base64 Encode the final output
	uint32_t b64_dst_len = ((blob.size() + 2) / 3) * 4 + 1;
	std::vector<uint8_t> b64_dst(b64_dst_len);

	if (dmCrypt::Base64Encode(blob.data(), blob.size(), b64_dst.data(), &b64_dst_len)) {
		lua_pushlstring(L, (const char*)b64_dst.data(), b64_dst_len);
	} else {
		secure_wipe(key.data(), key.size());
		secure_wipe(&ctx, sizeof(ctx));
		return luaL_error(L, "Base64 encoding failed.");
	}

	secure_wipe(key.data(), key.size());
	secure_wipe(&ctx, sizeof(ctx));
	return 1;
}

static const luaL_reg Module_methods[] = {
	{"encrypt_newgrounds", encrypt_newgrounds},
	{0, 0}
};

static void LuaInit(lua_State* L) {
	int top = lua_gettop(L);
	luaL_register(L, MODULE_NAME, Module_methods);
	lua_pop(L, 1);
}

static dmExtension::Result AppInitializeSecureString(dmExtension::AppParams* params) 
{ 
	
	return dmExtension::RESULT_OK; 
}


static dmExtension::Result InitializeSecureString(dmExtension::Params* params) 
{
	LuaInit(params->m_L);
	return dmExtension::RESULT_OK;
}
static dmExtension::Result AppFinalizeSecureString(dmExtension::AppParams* params) { return dmExtension::RESULT_OK; }
static dmExtension::Result FinalizeSecureString(dmExtension::Params* params) { return dmExtension::RESULT_OK; }

DM_DECLARE_EXTENSION(EXTENSION_NAME, LIB_NAME, AppInitializeSecureString, AppFinalizeSecureString, InitializeSecureString, 0, 0, FinalizeSecureString)