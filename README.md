Fish and Begol signature schemes
================================

This code represents a portation of the LowMC implementation from [1] to the
setting described in [2]. Some of the code, and in particular the basic LowMC
related methods, are taken from [1]. Methods for MPC computations are based on
[3].

Building
--------

To disable optimizations remove `-DWITH_OPT` from `CPPFLAGS` in `Makefile`.
Verbose output can be enabled by adding `-DVERBOSE`.

Dependencies
------------

* OpenSSL (libssl-dev)
* m4ri (libm4ri-dev)

References
----------

* [1] https://bitbucket.org/malb/lowmc-helib/src
* [2] https://eprint.iacr.org/2016/163.pdf
* [3] https://github.com/Sobuno/ZKBoo
