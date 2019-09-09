
#include "util.h"
#include "crypto-ops.h"
#include "random.h"
#include "crypto.h"

int check_scalar(uint8_t * scalar) {
  return sc_check(scalar) == 0;
}

void random_scalar(uint8_t *res)
{
  uint8_t tmp[64];
  generate_random_bytes_not_thread_safe(64, tmp);
  sc_reduce(tmp);
  memcpy(res, tmp, 32);
}

void hash_to_scalar(const uint8_t *data, size_t length, uint8_t *res)
{
  cn_fast_hash(data, length, res);
  sc_reduce32(res);
}

void generate_key_pair(uint8_t *pub, uint8_t *sec)
{
  ge_p3 point;
  random_scalar(sec);
  ge_scalarmult_base(&point, sec);
  ge_p3_tobytes(pub, &point);
}

int secret_key_to_public_key(const uint8_t *secret_key, uint8_t *public_key)
{
  ge_p3 point;
  if (sc_check(secret_key) != 0)
  {
    return 0;
  }
  ge_scalarmult_base(&point, secret_key);
  ge_p3_tobytes(public_key, &point);
  return 1;
}

int check_public_key(const uint8_t *public_key)
{
  ge_p3 point;
  return ge_frombytes_vartime(&point, public_key) == 0;
}
