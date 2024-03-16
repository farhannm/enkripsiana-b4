#pragma once
#ifndef FAREL_H
#define FAREL_H

#include <stdint.h>
#include "enkripsiana.h"

void keyExpansionCore(uint8_t* in, unsigned char i);
void keyExpansion(uint8_t* inputKey, uint8_t* expandedKeys);

#endif // !FAREL_H