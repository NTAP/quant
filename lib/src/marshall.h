// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2019, NetApp, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include <stdbool.h>
#include <stdint.h>


extern uint8_t __attribute__((const)) varint_size(const uint64_t val);

extern void __attribute__((nonnull))
enc1(uint8_t ** pos, const uint8_t * const end, const uint8_t val);

extern void __attribute__((nonnull))
enc2(uint8_t ** pos, const uint8_t * const end, const uint16_t val);

extern void __attribute__((nonnull))
enc3(uint8_t ** pos, const uint8_t * const end, const uint32_t val);

extern void __attribute__((nonnull))
enc4(uint8_t ** pos, const uint8_t * const end, const uint32_t val);

extern void __attribute__((nonnull))
enc8(uint8_t ** pos, const uint8_t * const end, const uint64_t val);

extern void __attribute__((nonnull))
encv(uint8_t ** pos, const uint8_t * const end, const uint64_t val);

extern void __attribute__((nonnull)) encvl(uint8_t ** pos,
                                           const uint8_t * const end,
                                           const uint64_t val,
                                           const uint8_t len);

extern void __attribute__((nonnull)) encb(uint8_t ** pos,
                                          const uint8_t * const end,
                                          const uint8_t * const val,
                                          const uint16_t len);

extern bool __attribute__((nonnull)) dec1(uint8_t * const val,
                                          const uint8_t ** const pos,
                                          const uint8_t * const end);

extern bool __attribute__((nonnull)) dec2(uint16_t * const val,
                                          const uint8_t ** const pos,
                                          const uint8_t * const end);

extern bool __attribute__((nonnull)) dec3(uint32_t * const val,
                                          const uint8_t ** const pos,
                                          const uint8_t * const end);

extern bool __attribute__((nonnull)) dec4(uint32_t * const val,
                                          const uint8_t ** const pos,
                                          const uint8_t * const end);

extern bool __attribute__((nonnull)) dec8(uint64_t * const val,
                                          const uint8_t ** const pos,
                                          const uint8_t * const end);

extern bool __attribute__((nonnull)) decv(uint64_t * const val,
                                          const uint8_t ** const pos,
                                          const uint8_t * const end);

extern bool __attribute__((nonnull)) decb(uint8_t * const val,
                                          const uint8_t ** const pos,
                                          const uint8_t * const end,
                                          const uint16_t len);
