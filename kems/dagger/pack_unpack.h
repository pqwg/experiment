#ifndef PACK_UNPACK_H
#define PACK_UNPACK_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include "SABER_params.h"

void SABER_pack_2bit(uint8_t *bytes, uint16_t *data);
void SABER_un_pack2bit(uint8_t *bytes, uint16_t *data);

void SABER_pack_3bit(uint8_t *bytes, uint16_t *data);
void SABER_un_pack3bit(uint8_t *bytes, uint16_t *data);

void SABER_pack_4bit(uint8_t *bytes, uint16_t *data);
void SABER_un_pack4bit(const unsigned char *bytes, uint16_t *ar);

void SABER_pack_6bit(uint8_t *bytes, uint16_t *data);
void SABER_un_pack6bit(const unsigned char *bytes, uint16_t *data);


void BS2POL(const unsigned char *bytes, uint16_t data[SABER_N]);

void POLVEC2BS(uint8_t *bytes, uint16_t data[SABER_K][SABER_N], uint16_t modulus);

void BS2POLVEC(const unsigned char *bytes, uint16_t data[SABER_K][SABER_N], uint16_t modulus);

#endif
