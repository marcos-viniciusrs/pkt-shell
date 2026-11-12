#!/bin/sh
# Packet Tracer .pkt/.pka <-> XML, usando libgcrypt e zlib do sistema.
# Algoritmo: https://github.com/izerhaf7/python-pka-to-xml
# Referencia: commit 23f1387f8bf5725c98215be7d7bb611c681a9484 (licenca MIT).
# Implementacao em shell com auxiliar C embutido; nao requer Python.
set -eu
umask 077

usage() {
    cat <<'HELP'
Uso: pkt-shell.sh [--force] decode ENTRADA.pkt SAIDA.xml
     pkt-shell.sh [--force] encode ENTRADA.xml SAIDA.pkt

Aceita tambem .pka e saida de texto .txt. Nao sobrescreve arquivos por padrao.
Requer: compilador cc, headers/bibliotecas libgcrypt e zlib, e GNU coreutils.
Limite: 512 MiB por arquivo e por XML descompactado.
HELP
}
fail() { printf 'Erro: %s\n' "$*" >&2; exit 1; }

force=no
if [ "${1-}" = --force ]; then force=yes; shift; fi
case "${1-}" in -h|--help) usage; exit 0 ;; esac
[ "$#" -eq 3 ] || { usage >&2; exit 2; }
mode=$1
case "$mode" in decode|encode) ;; *) usage >&2; exit 2 ;; esac
# Caminhos absolutos impedem que nomes iniciados com '-' virem opcoes.
case "$2" in /*) input=$2 ;; *) input=$PWD/$2 ;; esac
case "$3" in /*) output=$3 ;; *) output=$PWD/$3 ;; esac
[ -f "$input" ] && [ -r "$input" ] || fail "entrada nao e um arquivo legivel: $input"
[ ! "$input" -ef "$output" ] || fail 'entrada e saida apontam para o mesmo arquivo'
[ ! -d "$output" ] || fail 'a saida deve ser um arquivo, nao um diretorio'
if [ "$force" = no ] && { [ -e "$output" ] || [ -L "$output" ]; }; then
    fail "saida ja existe (use --force para substituir): $output"
fi
for tool in cc mktemp cat dirname ln mv rm; do
    command -v "$tool" >/dev/null 2>&1 || fail "programa necessario nao encontrado: $tool"
done

work=$(mktemp -d "${TMPDIR:-/tmp}/pkt-shell.XXXXXXXX")
staged=
cleanup() {
    if [ -n "$staged" ]; then rm -f -- "$staged"; fi
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

cat > "$work/codec.c" <<'C_SOURCE'
/* Native reimplementation of the Packet Tracer codec described by
 * izerhaf7/python-pka-to-xml, commit 23f1387. See accompanying README.
 * Uses libgcrypt's authenticated EAX implementation, not a custom cipher.
 */
#include <gcrypt.h>
#include <zlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LIMIT ((size_t)512 * 1024 * 1024)

static void die(const char *message) {
    fprintf(stderr, "Erro: %s\n", message);
    exit(EXIT_FAILURE);
}
static void check(gcry_error_t error, const char *operation) {
    if (error) {
        fprintf(stderr, "Erro: %s: %s\n", operation, gcry_strerror(error));
        exit(EXIT_FAILURE);
    }
}
static unsigned char *alloc(size_t size) {
    unsigned char *p = malloc(size ? size : 1);
    if (!p) die("memoria insuficiente");
    return p;
}
static unsigned char *read_file(const char *path, size_t *size) {
    FILE *f = fopen(path, "rb");
    if (!f) die("nao foi possivel abrir a entrada");
    if (fseek(f, 0, SEEK_END)) die("nao foi possivel medir a entrada");
    long length = ftell(f);
    if (length < 0 || (unsigned long)length > LIMIT)
        die("entrada excede o limite de 512 MiB ou tem tamanho invalido");
    rewind(f);
    *size = (size_t)length;
    unsigned char *data = alloc(*size);
    if (fread(data, 1, *size, f) != *size || ferror(f))
        die("falha ao ler a entrada");
    if (fclose(f)) die("falha ao fechar a entrada");
    return data;
}
static void write_file(const char *path, const unsigned char *data, size_t size) {
    FILE *f = fopen(path, "wb");
    if (!f) die("nao foi possivel abrir a saida temporaria");
    if (fwrite(data, 1, size, f) != size) die("falha ao escrever a saida");
    if (fclose(f)) die("falha ao fechar a saida");
}
static gcry_cipher_hd_t cipher(void) {
    gcry_cipher_hd_t handle;
    unsigned char key[16], iv[16];
    memset(key, 0x89, sizeof key);
    memset(iv, 0x10, sizeof iv);
    check(gcry_cipher_open(&handle, GCRY_CIPHER_TWOFISH128,
                           GCRY_CIPHER_MODE_EAX, 0), "inicializar Twofish-EAX");
    check(gcry_cipher_setkey(handle, key, sizeof key), "definir chave");
    check(gcry_cipher_setiv(handle, iv, sizeof iv), "definir IV");
    return handle;
}
/* The outer position mask depends only on the low byte of n and i.
 * This equivalent expression avoids size_t multiplication overflow. */
static unsigned char mask(size_t n, size_t i) {
    unsigned int low = (unsigned int)(n & 255);
    return (unsigned char)(low - (unsigned int)(i & 255) * low);
}
static void decode(unsigned char *input, size_t n, const char *output) {
    if (n < 20) die("arquivo curto demais para o formato PKT/PKA moderno");
    unsigned char *outer = alloc(n);
    for (size_t i = 0; i < n; ++i)
        outer[i] = input[n - 1 - i] ^ mask(n, i);
    size_t m = n - 16;
    unsigned char *inner = alloc(m);
    gcry_cipher_hd_t handle = cipher();
    check(gcry_cipher_decrypt(handle, inner, m, outer, m), "decifrar");
    /* Authenticate before decompression or publication of any plaintext. */
    check(gcry_cipher_checktag(handle, outer + m, 16),
          "validar autenticacao EAX (arquivo alterado, incompativel ou corrompido)");
    gcry_cipher_close(handle);
    free(outer);
    for (size_t i = 0; i < m; ++i)
        inner[i] ^= (unsigned char)((m - i) & 255);
    uint32_t expected = ((uint32_t)inner[0] << 24) |
                        ((uint32_t)inner[1] << 16) |
                        ((uint32_t)inner[2] << 8) | (uint32_t)inner[3];
    if (expected > LIMIT) die("XML declarado excede o limite de 512 MiB");
    unsigned char *xml = alloc(expected);
    uLongf size = expected ? expected : 1;
    uLong compressed = (uLong)(m - 4);
    int result = uncompress2(xml, &size, inner + 4, &compressed);
    if (result != Z_OK) die("fluxo zlib invalido ou tamanho declarado incorreto");
    if (size != expected || compressed != m - 4)
        die("tamanho descompactado incorreto ou dados extras depois do zlib");
    write_file(output, xml, (size_t)size);
    free(xml);
    free(inner);
}
static void encode(unsigned char *xml, size_t size, const char *output) {
    uLongf compressed = compressBound((uLong)size);
    unsigned char *inner = alloc((size_t)compressed + 4);
    inner[0] = (unsigned char)(size >> 24);
    inner[1] = (unsigned char)(size >> 16);
    inner[2] = (unsigned char)(size >> 8);
    inner[3] = (unsigned char)size;
    if (compress2(inner + 4, &compressed, xml, (uLong)size,
                  Z_DEFAULT_COMPRESSION) != Z_OK) die("falha na compressao zlib");
    size_t m = (size_t)compressed + 4, n = m + 16;
    if (n > LIMIT) die("PKT resultante excede o limite de 512 MiB");
    for (size_t i = 0; i < m; ++i)
        inner[i] ^= (unsigned char)((m - i) & 255);
    unsigned char *outer = alloc(n), *result = alloc(n);
    gcry_cipher_hd_t handle = cipher();
    check(gcry_cipher_encrypt(handle, outer, m, inner, m), "cifrar");
    check(gcry_cipher_gettag(handle, outer + m, 16), "gerar autenticacao EAX");
    gcry_cipher_close(handle);
    for (size_t i = 0; i < n; ++i)
        result[n - 1 - i] = outer[i] ^ mask(n, i);
    write_file(output, result, n);
    free(result);
    free(outer);
    free(inner);
}
int main(int argc, char **argv) {
    if (argc != 4) die("uso interno: codec decode|encode entrada saida");
    if (!gcry_check_version("1.7.0")) die("requer libgcrypt 1.7.0 ou superior");
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    size_t size;
    unsigned char *input = read_file(argv[2], &size);
    if (!strcmp(argv[1], "decode")) decode(input, size, argv[3]);
    else if (!strcmp(argv[1], "encode")) encode(input, size, argv[3]);
    else die("operacao desconhecida");
    free(input);
    return EXIT_SUCCESS;
}
C_SOURCE

if ! cc -std=c99 -O2 -Wall -Wextra -Werror "$work/codec.c" -o "$work/codec" -lgcrypt -lz; then
    fail 'compilacao falhou. Instale cc e os pacotes de desenvolvimento de libgcrypt e zlib (veja README.md).'
fi

# Criar no diretorio de destino permite publicar o resultado atomicamente.
staged=$(mktemp "$(dirname -- "$output")/.pkt-shell-output.XXXXXXXX")
"$work/codec" "$mode" "$input" "$staged"
if [ "$force" = yes ]; then
    mv -fT -- "$staged" "$output"
else
    # ln falha se o destino surgir durante a conversao; nunca o sobrescreve.
    ln -T -- "$staged" "$output" || fail 'nao foi possivel publicar a saida; o destino pode ja existir'
    rm -f -- "$staged"
fi
staged=
printf 'Concluido: %s\n' "$output"
