#include <cassert>
#include <vector>
#include <iostream>
#include <iomanip>

using namespace std;

#include "types.h"

vector<signature_t> signatures;
size_t sig_size;

void printBinary(const uint8_t *ptr, size_t size)
{
  std::cout << "[";
  for (int i = 0; i < size; i++)
  {
    if (i != 0)
    {
      std::cout << ", ";
    }
    std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(ptr[i]);
  }
  std::cout << "]" << std::endl;
}

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

    // printBinary(key, 64);
    // const uint8_t *key1 = (uint8_t *)&sign;
    // printBinary(key1, 64);
    signatures[i] = sign;
  }

  const uint8_t *sig_data()
  {
    printBinary((const uint8_t *)signatures.data(), 64 * sig_size);

    return (const uint8_t *)signatures.data();
  }
}
