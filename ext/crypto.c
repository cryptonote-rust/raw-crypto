
#include "util.h"
#include "crypto-ops.h"

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