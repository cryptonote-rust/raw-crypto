#include <cassert>
#include <vector>
#include "types.h"

using namespace std;

vector<public_key_t> vpubs;
vector<const public_key_t *> pubs;
size_t vec_size;

extern "C"
{

  void vec_resize(size_t new_size)
  {
    vec_size = new_size;
    vpubs.resize(new_size);
    pubs.resize(new_size);
  }

  void vec_clear()
  {
    vec_size = 0;
    vpubs.clear();
    pubs.clear();
  }

  void vec_push(size_t i, const uint8_t *key)
  {
    assert(vec_size > i);
    vpubs[i] = *(public_key_t *)key;
    pubs[i] = &vpubs[i];
  }

  const uint8_t *const *vec_data()
  {
    return (const uint8_t *const *)pubs.data();
  }
}
