
#include "util.h"
#include "crypto-ops.h"
#include "random.h"

void random_scalar(uint8_t *res)
{
  unsigned char tmp[64];
  generate_random_bytes(64, tmp);
  sc_reduce(tmp);
  memcpy(&res, tmp, 32);
}

void hash_to_scalar(const uint8_t *data, size_t length, uint8_t * res)
{
  cn_fast_hash(data, length, res);
  sc_reduce32(res);
}

void generate_keys(uint8_t * pub, uint8_t *sec)
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
