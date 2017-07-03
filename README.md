Fish and signature schemes
==========================

This code represents an implementation of the Fish signature scheme [1]. It uses
(a bit-sliced version of) LowMC [3,4] in the setting of ZKBoo [2]. Some methods
for MPC computations are based on [5].

Building
--------

First configure the build cmake and then run make:

```sh
mkdir build; cd build
cmake ..
make
```

Dependencies
------------

* OpenSSL (libssl-dev)
* m4ri (libm4ri-dev)

License
-------

The code is licensed under the MIT license.

Authors
-------

The code was written by David Derler and Sebastian Ramacher from [Institute for
Applied Information Processing and Communications, Graz University of
Technology](https://www.iaik.tugraz.at). They can be contacted via
<mailto:firstname.lastname@iaik.tugraz.at>.

References
----------

* [1] https://eprint.iacr.org/2017/279
* [2] https://eprint.iacr.org/2016/163
* [3] https://eprint.iacr.org/2016/687
* [4] https://bitbucket.org/malb/lowmc-helib
* [5] https://github.com/Sobuno/ZKBoo
