#include "randomness.h"
#include <bitset>

// Uses the Grain LSFR as self-shrinking generator to create pseudorandom bits
bool getrandbit () {
  static std::bitset<80> state; //Keeps the 80 bit LSFR state
  bool tmp = 0;
  //If state has not been initialized yet
  if (state.none ()) {
    state.set (); //Initialize with all bits set
    //Throw the first 160 bits away
    for (unsigned i = 0; i < 160; ++i) {
      //Update the state
      tmp =  state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62];
      state >>= 1;
      state[79] = tmp;
    }
  }
  //choice records whether the first bit is 1 or 0.
  //The second bit is produced if the first bit is 1.
  bool choice = false;
  do {
    //Update the state
    tmp =  state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62];
    state >>= 1;
    state[79] = tmp;
    choice = tmp;
    tmp =  state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62];
    state >>= 1;
    state[79] = tmp;
  } while (!choice);
  return tmp;
}
