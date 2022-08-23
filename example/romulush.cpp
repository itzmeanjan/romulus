#include "romulush.hpp"

#include <iostream>

#include "utils.hpp"

// Compile it with
//
// g++ -Wall -std=c++20 -O3 -march=native -I include example/romulush.cpp
int main() {
  constexpr size_t mlen = 48ul;
  constexpr size_t dlen = 32ul;

  uint8_t *msg = static_cast<uint8_t *>(std::malloc(mlen));
  uint8_t *dig = static_cast<uint8_t *>(std::malloc(dlen));

  random_data(msg, mlen);
  std::memset(dig, 0, dlen);

  romulush::hash(msg, mlen, dig);

  std::cout << "Romulus-H Hash Function" << std::endl << std::endl;
  std::cout << "Message : " << to_hex(msg, mlen) << std::endl;
  std::cout << "Digest  : " << to_hex(dig, dlen) << std::endl;

  std::free(msg);
  std::free(dig);

  return EXIT_SUCCESS;
}
