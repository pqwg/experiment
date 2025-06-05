/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef ENCODING_H
#define ENCODING_H

#include <stdbool.h>
#include <stdint.h>
#include "containers.h"

#include "uapi/linux/linux/wireguard.h"

#define ENCODING_FUNCTION(name) name ## _initiator_private
#define WG_KEY_LEN WG_INITIATOR_PRIVATE_KEY_LEN
#include "encoding_header.inc"

#define ENCODING_FUNCTION(name) name ## _initiator_public
#define WG_KEY_LEN WG_INITIATOR_PUBLIC_KEY_LEN
#include "encoding_header.inc"

#define ENCODING_FUNCTION(name) name ## _responder_private
#define WG_KEY_LEN WG_RESPONDER_PRIVATE_KEY_LEN
#include "encoding_header.inc"

#define ENCODING_FUNCTION(name) name ## _responder_public
#define WG_KEY_LEN WG_RESPONDER_PUBLIC_KEY_LEN
#include "encoding_header.inc"


#define ENCODING_FUNCTION(name) name ## _psk
#define WG_KEY_LEN WG_PSK_KEY_LEN
#include "encoding_header.inc"



#define MAX(a,b) (((a)>(b))?(a):(b))
#define WG_KEY_LEN_MAX MAX(WG_INITIATOR_PRIVATE_KEY_LEN, MAX(WG_RESPONDER_PRIVATE_KEY_LEN, MAX(WG_INITIATOR_PUBLIC_KEY_LEN, WG_RESPONDER_PUBLIC_KEY_LEN)))
#define WG_KEY_LEN_HEX_MAX (WG_KEY_LEN_MAX * 2 + 1)
#endif
