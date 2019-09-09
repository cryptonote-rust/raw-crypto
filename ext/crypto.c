
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

void scalar_to_hash(const uint8_t *data, size_t length, uint8_t *hash)
{
  cn_fast_hash(data, length, hash);
  sc_reduce32(hash);
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


  int generate_key_derivation(const uint8_t *key1, const uint8_t *key2, uint8_t *derivation) {
    ge_p3 point;
    ge_p2 point2;
    ge_p1p1 point3;
    assert(sc_check(key2) == 0);
    if (ge_frombytes_vartime(&point, key1) != 0) {
      return false;
    }
    ge_scalarmult(&point2, key2, &point);
    ge_mul8(&point3, &point2);
    ge_p1p1_to_p2(&point2, &point3);
    ge_tobytes(derivation, &point2);
    return true;
  }