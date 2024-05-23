#pragma warning(disable : 4996)
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctime>
#include "enkripsiana.h"
#include "dirent.h"
#include "uihead.h"

// Fungsi untuk mengatur posisi kursor di konsol
void SetPost(int row, int column)
{
    HANDLE consoleHandle;      // Mendeklarasikan variabel untuk menangani konsol
    COORD cursorPosition;      // Mendeklarasikan variabel untuk menyimpan koordinat kursor
    cursorPosition.Y = row;    // Mengatur posisi baris kursor (sumbu Y) sesuai dengan parameter row
    cursorPosition.X = column; // Mengatur posisi kolom kursor (sumbu X) sesuai dengan parameter column
    consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE); // Mendapatkan handle standar untuk output konsol
    SetConsoleCursorPosition(consoleHandle, cursorPosition); // Mengatur posisi kursor di konsol sesuai dengan koordinat yang ditentukan
}

// Fungsi untuk mengatur warna teks di konsol
void SetTextColor(int foregroundColor, int backgroundColor)
{
    HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE); // Mendapatkan handle standar untuk output konsol
    SetConsoleTextAttribute(consoleHandle, foregroundColor | backgroundColor); // Mengatur atribut teks konsol (warna teks dan/atau latar belakang)
}

// Fungsi untuk mengembalikan warna teks ke pengaturan default
void ResetTextColor()
{
    HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE); // Mendapatkan handle standar untuk output konsol
    SetConsoleTextAttribute(consoleHandle, 0 | 7); // Mengatur atribut teks konsol ke warna default (latar belakang hitam dan teks putih)
}


void banner()
{
    SetTextColor(NONE, FG_YELLOW);
    SetPost(0, 4); printf("%c%c%c%c%c%c%c%c%c%c%c%c  %c%c%c%c%c%c  %c%c%c\n", 219, 219, 219, 219, 219, 219, 219, 187, 219, 219, 219, 187, 219, 219, 187, 219, 219, 187, 219, 219, 187, 219, 219, 219, 219, 219, 219, 187, 219, 219, 187, 219, 219, 219, 219, 219, 219, 187, 219, 219, 219, 219, 219, 219, 219, 187);
    SetPost(1, 4); printf("%c%c%c%c%c%c%c%c%c%c%c%c%c %c%c%c%c%c%c %c%c%c%c\n", 219, 219, 201, 205, 205, 205, 205, 188, 219, 219, 219, 219, 187, 219, 219, 186, 219, 219, 186, 219, 219, 201, 188, 219, 219, 201, 205, 205, 219, 219, 186, 219, 219, 186, 219, 219, 201, 205, 205, 219, 219, 186, 219, 219, 201, 205, 205, 205, 205, 205, 188);
    SetPost(2, 4); printf("%c%c%c%c%c%c  %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", 219, 219, 219, 219, 219, 187, 219, 219, 186, 219, 219, 187, 219, 219, 186, 219, 219, 219, 219, 219, 201, 188, 219, 219, 219, 219, 219, 219, 201, 188, 219, 219, 186, 219, 219, 219, 219, 219, 219, 201, 188, 219, 219, 219, 219, 219, 219, 187);
    SetPost(3, 4); printf("%c%c%c%c%c%c  %c%c%c %c%c%c%c%c%c%c%c%c%c%c%c\n", 219, 219, 201, 205, 205, 188, 219, 219, 186, 219, 219, 219, 219, 186, 219, 219, 201, 205, 219, 219, 187, 219, 219, 201, 205, 219, 219, 186, 219, 219, 186, 219, 219, 201, 205, 205, 205, 188, 200, 205, 205, 205, 205, 219, 219, 187);
    SetPost(4, 4); printf("%c%c%c%c%c%c%c%c%c%c%c  %c%c%c%c%c%c%c  %c%c%c\n", 219, 219, 219, 219, 219, 219, 219, 187, 219, 219, 186, 219, 219, 219, 186, 219, 219, 186, 219, 219, 187, 219, 219, 186, 219, 219, 187, 219, 219, 186, 219, 219, 186, 219, 219, 219, 219, 219, 219, 219, 201, 188);
    SetPost(5, 4); printf("%c%c%c%c%c%c%c%c%c%c%c  %c%c%c%c%c%c%c  %c%c%c\n", 200, 205, 205, 205, 205, 205, 205, 188, 200, 205, 188, 200, 205, 205, 188, 200, 205, 188, 200, 205, 188, 200, 205, 188, 200, 205, 188, 200, 205, 188, 200, 205, 188, 200, 205, 205, 205, 205, 205, 205, 188);
    ResetTextColor();
}
