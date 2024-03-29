// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2022, NetApp, Inc.
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

#include <Particle.h>

#include "minimal_transaction.h"
#include "quant/quant.h"


SYSTEM_MODE(MANUAL);
// SYSTEM_THREAD(ENABLED);

#if !defined(NDEBUG) || defined(DSTACK)
static SerialDebugOutput serial;
#endif

static const int led = D7;


// don't use entropy from cloud
void random_seed_from_cloud(unsigned int seed) {}


static ApplicationWatchdog wd(60000, System.reset);

extern "C" void ping(void)
{
    wd.checkin();
}



void button_action()
{
    Serial.begin(9600);
    delay(1000);

    WiFi.on();
    WiFi.connect(WIFI_CONNECT_SKIP_LISTEN);
    waitUntil(WiFi.ready);
    digitalWrite(led, HIGH);

    warn(DBG, "Particle Device OS: %lu.%lu.%lu",
         (System.versionNumber() & 0xff000000) >> 24,
         (System.versionNumber() & 0x00ff0000) >> 16,
         (System.versionNumber() & 0x0000ff00) >> 8);

    // char msg[64];
    // const float voltage = analogRead(BATT) * 0.0011224;
    // const size_t msg_len = snprintf(
    //     msg, sizeof(msg), "Hello from Particle! Voltage is %f.", voltage);
    // warpcore_transaction(msg, msg_len);

    static const char req[] = "GET /5000\r\n";
    quic_transaction(req, sizeof(req));

    WiFi.off();
    digitalWrite(led, LOW);
}


void setup()
{
    // let's gather some entropy and seed the RNG
    const int temp = analogRead(A0);
    const int volt = analogRead(BATT);
    randomSeed(((temp << 12) | volt));

    pinMode(led, OUTPUT);
    button_action();
}


void loop()
{
    System.sleep(BTN, FALLING);
    if (System.sleepResult().reason() == WAKEUP_REASON_PIN)
        button_action();
}
