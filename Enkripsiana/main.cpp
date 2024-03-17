#pragma warning(disable : 4996)
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dirent.h"
#include "enkripsiana.h"

int main()
{
    int opsi;
    bool isValid;

    printf("+-------------------------------+\n");
    printf("|     E N K R I P S I A N A     |\n");
    printf("+-------------------------------+\n");

    do {
        printf("\nPilih aksi yang akan dilakukan : \n");
        printf("(1). Buat File \n");
        printf("(2). Enkripsi \n");
        printf("(3). Deskripsi\n");
        printf("(4). Keluar dari aplikasi \n");
        printf("\n[>>] Masukkan pilihan (1-4) : ");
        scanf("%d", &opsi);

        switch (opsi) {
        case 1:
            system("cls");
            printf("+----------------------------------+\n");
            printf("|             Buat File            |\n");
            printf("+----------------------------------+\n\n");

            return BuatFile();
            isValid = true;

            break;
        case 2:
            system("cls");
            printf("+----------------------------------+\n");
            printf("|              Enkripsi            |\n");
            printf("+----------------------------------+\n\n");

            return encryptFile();
            isValid = true;
            break;
        case 3:
            system("cls");
            printf("+--------------------------------+\n");
            printf("|            Deskripsi           |\n");
            printf("+--------------------------------+\n");

            isValid = true;
            break;
        case 4:
            printf("\nKeluar dari aplikasi...\n");
            exit(0);
            break;
        default:
            printf("\nInput tidak valid. Masukkan angka antara 1 hingga 3.\n");
            isValid = false;
            break;

        }

    } while (!isValid);

    return 0;
}


