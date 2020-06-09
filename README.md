# Quant

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/ec5037ef95ce4b358c10a8106c77454e)](https://app.codacy.com/manual/larseggert/quant?utm_source=github.com&utm_medium=referral&utm_content=NTAP/quant&utm_campaign=Badge_Grade_Dashboard)
[![Build Status](https://travis-ci.org/NTAP/quant.svg?branch=master)](https://travis-ci.org/NTAP/quant)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/NTAP/quant.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/NTAP/quant/alerts/)

Quant is a BSD-licensed C11 implementation of the emerging IETF
[QUIC](https://quicwg.github.io/) standard for a new transport protocol over
UDP, intending to support the new HTTP/3 standard and other application
protocols.

Quant uses the [warpcore](https://github.com/NTAP/warpcore) zero-copy userspace
UDP/IP stack, which in addition to running on on top of the standard **Socket
API** has support for the **[netmap](http://info.iet.unipi.it/~luigi/netmap/)**
fast packet I/O framework, as well as the
**[Particle](https://github.com/particle-iot/device-os)** and
**[RIOT](http://riot-os.org/)** IoT stacks. Quant hence supports traditional
POSIX platforms (Linux, MacOS, FreeBSD, etc.) as well as embedded systems.

The quant repository is [on GitHub](https://github.com/NTAP/quant).

**NOTE:** Quant implements the QUIC transport layer, but does **NOT** implement
an HTTP/3 binding.


## Prerequisites

Quant uses [picotls](https://github.com/h2o/picotls) for its [TLS
1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-tls13/) implementation. and
[klib](https://github.com/attractivechaos/klib) and
[timeout](http://25thandclement.com/~william/projects/timeout.c.html) for some
data structures and functions. These dependencies will be built automatically.

The example HTTP/0.9 client and server use
[http-parser](https://github.com/nodejs/http-parser).

So you need to install some dependencies. On the Mac, the easiest way is via
[Homebrew](http://brew.sh/), so install that first. Then, do

    brew install cmake http-parser pkg-config

On Debian-based Linux systems, do

    apt install libssl-dev libhttp-parser-dev libbsd-dev pkgconf

On Darwin, you **must** also install the Xcode command line tools first:

    xcode-select --install

Quant uses the [cmake](https://cmake.org/) build system and
[Doxygen](http://www.doxygen.nl/) to generate the documentation. If doxygen is
available, th documentation can be locally built vi the `doc` target.



## Building
To do an out-of-source build of quant (best practice with `cmake`), do the
following to build with `make` as a generator:

    git submodule update --init --recursive
    mkdir Debug
    cd Debug
    cmake ..
    make

The default build (per above) is without optimizations and with extensive debug
logging enabled. In order to build an optimized build, do this:

    git submodule update --init --recursive
    mkdir Release
    cd Release
    cmake -DCMAKE_BUILD_TYPE=Release ..
    make

(I really recommend [Ninja](https://ninja-build.org/) over `make`.)


## Building for RIOT or Particle

Please see `README.md` in the `riot` and `particle` subdirectories.


## Docker container

Instead of building quant for yourself, you can also obtain a [pre-built Docker
container](https://cloud.docker.com/u/ntap/repository/docker/ntap/quant/). For
example,

    docker pull ntap/quant:latest

should download the latest build on the `master` branch. The docker container by
default exposes a QUIC server on port 4433 that can serve `/index.html` and
possibly other resources.

To map the UDP port, run the docker container with

    docker run -p4433:4433/udp ntap/quant


## Testing and interop

The `libquant` library will be in `lib`. There are `client` and `server`
examples in `bin`. They explain their usage when called with a `-h` argument.

The current interop status of quant against [other
stacks](https://github.com/quicwg/base-drafts/wiki/Implementations) is captured
in [this
spreadsheet](https://docs.google.com/spreadsheets/d/1D0tW89vOoaScs3IY9RGC0UesWGAwE6xyLk0l4JtvTVg/edit#gid=1510984897).


## Development and contributing

At the moment, development happens in `master`, and branches numbered according
to the [IETF Internet Drafts](https://quicwg.github.io/) they implement serve as
archives.

I'm happy to merge contributions that fix
[bugs](https://github.com/NTAP/quant/issues?q=is%3Aopen+is%3Aissue+label%3Abug)
or add
[features](https://github.com/NTAP/quant/issues?q=is%3Aopen+is%3Aissue+label%3Aenhancement).
Please send pull requests.

(Contributions to the underlying [warpcore](https://github.com/NTAP/warpcore)
stack are also very welcome.)


## Copyright

Copyright (c) 2016-2020, NetApp, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


## Acknowledgment

This software has received past funding from the European Union's Horizon 2020
research and innovation program 2014-2018 under grant agreement 644866
(["SSICLOPS"](https://ssiclops.eu/)). The European Commission is not responsible
for any use that may be made of this software.


[//]: # (@example client.c)
[//]: # (@example server.c)
