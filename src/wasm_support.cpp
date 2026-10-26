// Wasm only. aws-c-cal is built with BYO_CRYPTO there (no OpenSSL in the browser), so the hashes the SDK asks for
// come from DuckDB: SHA-256 / SHA-1 from its bundled mbedtls, MD5 from its own MD5Context (every AWSClient creates
// one at construction, whether or not the service ever sends Content-MD5), installed through aws-c-cal's
// aws_set_*_new_fn hooks. aws-c-io's socket layer is not compiled for wasm either, and two address parsers other
// CRT libraries still reference get definitions here.
#include "wasm_support.hpp"

#include "duckdb/common/crypto/md5.hpp"
#include "duckdb/common/typedefs.hpp"
#include "mbedtls_wrapper.hpp"

#include <aws/cal/hash.h>
#include <aws/cal/hmac.h>
#include <aws/common/allocator.h>
#include <aws/common/byte_buf.h>
#include <aws/common/error.h>
#include <aws/io/socket.h>

#include <cstring>
#include <string>

namespace duckdb {

namespace {

using duckdb_mbedtls::MbedTlsWrapper;

int WriteDigest(const std::string &digest, aws_byte_buf *out) {
	if (out->capacity - out->len < digest.size()) {
		return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
	}
	memcpy(out->buffer + out->len, digest.data(), digest.size());
	out->len += digest.size();
	return AWS_OP_SUCCESS;
}

// SHA-256 and SHA-1 over the wrapper's streaming states

struct Sha256Hash {
	MbedTlsWrapper::SHA256State state;
};

struct Sha1Hash {
	MbedTlsWrapper::SHA1State state;
};

template <class IMPL>
void HashDestroy(aws_hash *hash) {
	delete static_cast<IMPL *>(hash->impl);
	aws_mem_release(hash->allocator, hash);
}

int Sha256Update(aws_hash *hash, const aws_byte_cursor *buf) {
	if (!hash->good) {
		return aws_raise_error(AWS_ERROR_INVALID_STATE);
	}
	static_cast<Sha256Hash *>(hash->impl)->state.AddBytes(const_data_ptr_t(buf->ptr), buf->len);
	return AWS_OP_SUCCESS;
}

int Sha256Finalize(aws_hash *hash, aws_byte_buf *out) {
	if (!hash->good) {
		return aws_raise_error(AWS_ERROR_INVALID_STATE);
	}
	hash->good = false;
	return WriteDigest(static_cast<Sha256Hash *>(hash->impl)->state.Finalize(), out);
}

int Sha1Update(aws_hash *hash, const aws_byte_cursor *buf) {
	if (!hash->good) {
		return aws_raise_error(AWS_ERROR_INVALID_STATE);
	}
	static_cast<Sha1Hash *>(hash->impl)
	    ->state.AddString(std::string(reinterpret_cast<const char *>(buf->ptr), buf->len));
	return AWS_OP_SUCCESS;
}

int Sha1Finalize(aws_hash *hash, aws_byte_buf *out) {
	if (!hash->good) {
		return aws_raise_error(AWS_ERROR_INVALID_STATE);
	}
	hash->good = false;
	return WriteDigest(static_cast<Sha1Hash *>(hash->impl)->state.Finalize(), out);
}

struct Md5Hash {
	MD5Context context;
};

int Md5Update(aws_hash *hash, const aws_byte_cursor *buf) {
	if (!hash->good) {
		return aws_raise_error(AWS_ERROR_INVALID_STATE);
	}
	static_cast<Md5Hash *>(hash->impl)->context.Add(const_data_ptr_t(buf->ptr), buf->len);
	return AWS_OP_SUCCESS;
}

int Md5Finalize(aws_hash *hash, aws_byte_buf *out) {
	if (!hash->good) {
		return aws_raise_error(AWS_ERROR_INVALID_STATE);
	}
	hash->good = false;
	std::string digest(MD5Context::MD5_HASH_LENGTH_BINARY, '\0');
	static_cast<Md5Hash *>(hash->impl)->context.Finish(data_ptr_t(&digest[0]));
	return WriteDigest(digest, out);
}

aws_hash_vtable SHA256_VTABLE = {"SHA256", "mbedtls", HashDestroy<Sha256Hash>, Sha256Update, Sha256Finalize};
aws_hash_vtable SHA1_VTABLE = {"SHA1", "mbedtls", HashDestroy<Sha1Hash>, Sha1Update, Sha1Finalize};
aws_hash_vtable MD5_VTABLE = {"MD5", "duckdb", HashDestroy<Md5Hash>, Md5Update, Md5Finalize};

template <class IMPL>
aws_hash *HashNew(aws_allocator *allocator, aws_hash_vtable *vtable, size_t digest_size) {
	auto hash = static_cast<aws_hash *>(aws_mem_calloc(allocator, 1, sizeof(aws_hash)));
	if (!hash) {
		return nullptr;
	}
	hash->allocator = allocator;
	hash->vtable = vtable;
	hash->digest_size = digest_size;
	hash->good = true;
	hash->impl = new IMPL();
	return hash;
}

aws_hash *Sha256New(aws_allocator *allocator) {
	return HashNew<Sha256Hash>(allocator, &SHA256_VTABLE, MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES);
}

aws_hash *Sha1New(aws_allocator *allocator) {
	return HashNew<Sha1Hash>(allocator, &SHA1_VTABLE, MbedTlsWrapper::SHA1_HASH_LENGTH_BYTES);
}

aws_hash *Md5New(aws_allocator *allocator) {
	return HashNew<Md5Hash>(allocator, &MD5_VTABLE, MD5Context::MD5_HASH_LENGTH_BINARY);
}

// aws-c-cal's default for an unset hook is abort(); nothing here needs SHA-512, so it fails as an error instead
aws_hash *Sha512Unavailable(aws_allocator *allocator) {
	(void)allocator;
	aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
	return nullptr;
}

aws_hmac *HmacSha512Unavailable(aws_allocator *allocator, const aws_byte_cursor *secret) {
	(void)allocator;
	(void)secret;
	aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
	return nullptr;
}

// HMAC-SHA256 (RFC 2104) from the streaming SHA-256: the wrapper's own HMAC is one-shot, aws_hmac is incremental

constexpr size_t SHA256_BLOCK_BYTES = 64;

struct HmacSha256 {
	MbedTlsWrapper::SHA256State inner;
	unsigned char opad[SHA256_BLOCK_BYTES];
};

void HmacDestroy(aws_hmac *hmac) {
	delete static_cast<HmacSha256 *>(hmac->impl);
	aws_mem_release(hmac->allocator, hmac);
}

int HmacUpdate(aws_hmac *hmac, const aws_byte_cursor *buf) {
	if (!hmac->good) {
		return aws_raise_error(AWS_ERROR_INVALID_STATE);
	}
	static_cast<HmacSha256 *>(hmac->impl)->inner.AddBytes(const_data_ptr_t(buf->ptr), buf->len);
	return AWS_OP_SUCCESS;
}

int HmacFinalize(aws_hmac *hmac, aws_byte_buf *out) {
	if (!hmac->good) {
		return aws_raise_error(AWS_ERROR_INVALID_STATE);
	}
	hmac->good = false;
	auto impl = static_cast<HmacSha256 *>(hmac->impl);
	auto inner_digest = impl->inner.Finalize();
	MbedTlsWrapper::SHA256State outer;
	outer.AddBytes(const_data_ptr_t(impl->opad), SHA256_BLOCK_BYTES);
	outer.AddBytes(const_data_ptr_t(inner_digest.data()), inner_digest.size());
	return WriteDigest(outer.Finalize(), out);
}

aws_hmac_vtable HMAC_SHA256_VTABLE = {"HMAC-SHA256", "mbedtls", HmacDestroy, HmacUpdate, HmacFinalize};

aws_hmac *HmacSha256New(aws_allocator *allocator, const aws_byte_cursor *secret) {
	std::string key(reinterpret_cast<const char *>(secret->ptr), secret->len);
	if (key.size() > SHA256_BLOCK_BYTES) {
		MbedTlsWrapper::SHA256State key_hash;
		key_hash.AddBytes(const_data_ptr_t(key.data()), key.size());
		key = key_hash.Finalize();
	}
	key.resize(SHA256_BLOCK_BYTES, '\0');

	auto impl = new HmacSha256();
	unsigned char ipad[SHA256_BLOCK_BYTES];
	for (size_t i = 0; i < SHA256_BLOCK_BYTES; i++) {
		auto byte = static_cast<unsigned char>(key[i]);
		ipad[i] = byte ^ 0x36;
		impl->opad[i] = byte ^ 0x5c;
	}
	impl->inner.AddBytes(const_data_ptr_t(ipad), SHA256_BLOCK_BYTES);

	auto hmac = static_cast<aws_hmac *>(aws_mem_calloc(allocator, 1, sizeof(aws_hmac)));
	if (!hmac) {
		delete impl;
		return nullptr;
	}
	hmac->allocator = allocator;
	hmac->vtable = &HMAC_SHA256_VTABLE;
	hmac->digest_size = MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES;
	hmac->good = true;
	hmac->impl = impl;
	return hmac;
}

} // namespace

void RegisterWasmSupport() {
	aws_set_sha256_new_fn(Sha256New);
	aws_set_sha1_new_fn(Sha1New);
	aws_set_md5_new_fn(Md5New);
	aws_set_sha512_new_fn(Sha512Unavailable);
	aws_set_sha256_hmac_new_fn(HmacSha256New);
	aws_set_sha512_hmac_new_fn(HmacSha512Unavailable);
}

} // namespace duckdb

// aws-c-io compiles no socket layer for wasm; aws-c-auth and aws-c-http still reference these two
extern "C" int aws_parse_ipv4_address(const struct aws_string *src, uint32_t *dst) {
	(void)src;
	(void)dst;
	return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
}

extern "C" int aws_parse_ipv6_address(const struct aws_string *src, struct aws_byte_buf *dst) {
	(void)src;
	(void)dst;
	return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
}
