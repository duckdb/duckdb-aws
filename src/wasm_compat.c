// Compatibility shims for WebAssembly/Emscripten side-module builds.
//
// DuckDB-Wasm loadable extensions are linked with -sSIDE_MODULE=2: libc is
// expected to come from the main module. The duckdb-wasm main module does not
// export the network byte-order helpers, so provide them here (wasm32 is
// little-endian, these are plain byte swaps).
#ifdef __EMSCRIPTEN__

#include <stdint.h>

uint16_t htons(uint16_t x) {
	return (uint16_t)((x << 8) | (x >> 8));
}

uint16_t ntohs(uint16_t x) {
	return htons(x);
}

uint32_t htonl(uint32_t x) {
	return ((x & 0x000000FFu) << 24) | ((x & 0x0000FF00u) << 8) | ((x & 0x00FF0000u) >> 8) |
	       ((x & 0xFF000000u) >> 24);
}

uint32_t ntohl(uint32_t x) {
	return htonl(x);
}

#endif
