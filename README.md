libscep - A Client Side SCEP Library
====================================
[![Build Status](https://travis-ci.org/Javex/libscep.svg?branch=develop)](https://travis-ci.org/Javex/libscep)

`libscep` implements the 
[SCEP protocol](http://tools.ietf.org/html/draft-nourse-scep-23) as a C library
and additionally provides a command line client that allows to operate the 
program without need to write an implementation of this library.

The client is based on the classic [sscep](https://github.com/certnanny/sscep)
client and follows the same syntax. Internally it just wraps the library.

The library itself is pretty basic. It gets initialized, then one or multiple
operations can be executed and then it gets destroyed again.

*Note*: This is currently in development phase und not yet ready.

Compiling
----------

Dependencies:

    `openssl`, `cmake`, `pkg-config`, `check` (unit test framework for C),
    `uriparser` (liburiparser1, liburiparser-dev on debian),
    `libcurl4-openssl-dev`

    mkdir build
    cmake ..
    make
    make test
