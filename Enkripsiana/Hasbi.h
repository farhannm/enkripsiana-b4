#pragma once
#ifndef HASBI_H
#define HASBI_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

uint8_t gmul(uint8_t a, uint8_t b);
void mixColumns(uint8_t* state);

#endif // !HASBI_H