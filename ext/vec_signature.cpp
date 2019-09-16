#include <cassert>
#include <vector>
#include <iostream>
using namespace std;

#include "types.h"

vector<signature_t> signatures;
size_t sig_size;

extern "C"
{
  void sig_resize(size_t new_size)
  {
    sig_size = new_size;
    signatures.resize(new_size);
  }

  void sig_clear()
  {
    sig_size = 0;
    signatures.clear();
  }

  void sig_push(size_t i, const uint8_t *key)
  {
    assert(sig_size > i);
    signature_t sign = *(signature_t *)key;
    signatures[i] = sign;
  }

  const uint8_t *sig_data()
  {
    return (const uint8_t *)signatures.data();
  }
}
