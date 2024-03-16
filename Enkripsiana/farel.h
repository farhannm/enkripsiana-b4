#pragma once
#ifndef FAREL_H
#define FAREL_H

#include <stdint.h>
#include "enkripsiana.h"

void keyExpansionCore(unsigned char* in, unsigned char i);
void keyExpansion(unsigned char* inputKey, unsigned char* expandedKeys);

#endif // !FAREL_H