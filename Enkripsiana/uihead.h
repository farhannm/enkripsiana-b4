#include <windows.h>
#include <stdbool.h>
#include <conio.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

/* Define Kode Warna */
#define FG_BLACK 0x00
#define FG_BLUE 0x01
#define FG_GREEN 0x02
#define FG_CYAN 0x03
#define FG_RED 0x04
#define FG_MAGENTA 0x05
#define FG_YELLOW 0x06
#define FG_WHITE 0x07

#define BG_BLACK 0x00
#define BG_BLUE 0x10
#define BG_GREEN 0x20
#define BG_CYAN 0x30
#define BG_RED 0x40
#define BG_MAGENTA 0x50
#define BG_YELLOW 0x60
#define BG_WHITE 0x70

// Definisi kombinasi warna baru
#define FG_CREAM (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define FG_LIGHT_BLUE (FG_BLUE | FOREGROUND_INTENSITY)
#define FG_LIGHT_GREEN (FG_GREEN | FOREGROUND_INTENSITY)
#define FG_LIGHT_CYAN (FG_CYAN | FOREGROUND_INTENSITY)
#define FG_LIGHT_RED (FG_RED | FOREGROUND_INTENSITY)
#define FG_LIGHT_MAGENTA (FG_MAGENTA | FOREGROUND_INTENSITY)
#define FG_LIGHT_YELLOW (FG_YELLOW | FOREGROUND_INTENSITY)
#define FG_LIGHT_WHITE (FG_WHITE | FOREGROUND_INTENSITY)

// Definisi kombinasi warna foreground dan background
#define FG_CREAM_BG_BLUE (FG_CREAM | BG_BLUE)
#define FG_LIGHT_RED_BG_YELLOW (FG_LIGHT_RED | BG_YELLOW)
#define FG_LIGHT_GREEN_BG_MAGENTA (FG_LIGHT_GREEN | BG_MAGENTA)
#define FG_LIGHT_CYAN_BG_RED (FG_LIGHT_CYAN | BG_RED)
#define FG_LIGHT_BLUE_BG_GREEN (FG_LIGHT_BLUE | BG_GREEN)
#define FG_LIGHT_MAGENTA_BG_CYAN (FG_LIGHT_MAGENTA | BG_CYAN)

#define NONE 0

void SetPost(int row, int column);
void SetTextColor(int foregroundColor, int backgroundColor);
void ResetTextColor();
void banner();
