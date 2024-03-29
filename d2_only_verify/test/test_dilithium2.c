#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "api.h"

#define	MAX_MARKER_LEN		50

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int VerifySignature(const char *filename);

int main() {
    const char *rsp_filename = "PQCsignKAT_"; // Provide the filename here
    int result = VerifySignature(rsp_filename);
    if (result == KAT_SUCCESS) {
        printf("Verification successful.\n");
    } else {
        printf("Verification failed.\n");
    }
    return result;
}

int VerifySignature(const char *filename) {
    char fn_rsp[32];
    FILE *fp_rsp;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sm[CRYPTO_BYTES + 3300]; // Extra space for signature
    unsigned char m[3300];
    unsigned long long smlen, mlen;
    int count;

    sprintf(fn_rsp, "%s%d.rsp", filename, CRYPTO_SECRETKEYBYTES);

    if ((fp_rsp = fopen(fn_rsp, "r")) == NULL) {
        printf("Couldn't open <%s> for read\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }

    while (fscanf(fp_rsp, "count = %d\n", &count) == 1) {
        if (!ReadHex(fp_rsp, pk, CRYPTO_PUBLICKEYBYTES, "pk = ")) {
            printf("ERROR: unable to read 'pk' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }

        if (!ReadHex(fp_rsp, sm, CRYPTO_BYTES, "sm = ")) {
            printf("ERROR: unable to read 'sm' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }

        if (!ReadHex(fp_rsp, m, 3300, "msg = ")) {
            printf("ERROR: unable to read 'msg' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }

        if (!FindMarker(fp_rsp, "smlen = ")) {
            printf("ERROR: unable to read 'smlen' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }
        fscanf(fp_rsp, "%llu\n", &smlen);

        if (!FindMarker(fp_rsp, "\n\n")) {
            printf("ERROR: unable to find separator in <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }

        int ret_val = crypto_sign_open(m, &mlen, sm, smlen, pk);
        if (ret_val != 0) {
            printf("crypto_sign_open returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }

        if (mlen != smlen - CRYPTO_BYTES) {
            printf("Invalid signature length.\n");
            return KAT_CRYPTO_FAILURE;
        }

        if (memcmp(m, sm + CRYPTO_BYTES, mlen) != 0) {
            printf("Signature verification failed.\n");
            return KAT_CRYPTO_FAILURE;
        }
    }

    fclose(fp_rsp);
    return KAT_SUCCESS;
}

int FindMarker(FILE *infile, const char *marker) {
    char line[MAX_MARKER_LEN];
    int len = (int)strlen(marker);

    for (int i = 0; i < len; i++) {
        int curr_line = fgetc(infile);
        if (curr_line == EOF)
            return 0;
        line[i] = curr_line;
    }
    line[len] = '\0';

    while (1) {
        if (!strncmp(line, marker, len))
            return 1;

        for (int i = 0; i < len - 1; i++)
            line[i] = line[i + 1];
        int curr_line = fgetc(infile);
        if (curr_line == EOF)
            return 0;
        line[len - 1] = curr_line;
        line[len] = '\0';
    }

    return 0;
}

int ReadHex(FILE *infile, unsigned char *A, int Length, const char *str) {
    int i, ch, started;
    unsigned char ich;

    if (Length == 0) {
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, Length);
    started = 0;
    if (FindMarker(infile, str))
        while ((ch = fgetc(infile)) != EOF) {
            if (!isxdigit(ch)) {
                if (!started) {
                    if (ch == '\n')
                        break;
                    else
                        continue;
                } else
                    break;
            }
            started = 1;
            if ((ch >= '0') && (ch <= '9'))
                ich = ch - '0';
            else if ((ch >= 'A') && (ch <= 'F'))
                ich = ch - 'A' + 10;
            else if ((ch >= 'a') && (ch <= 'f'))
                ich = ch - 'a' + 10;
            else // shouldn't ever get here
                ich = 0;

            for (i = 0; i < Length - 1; i++)
                A[i] = (A[i] << 4) | (A[i + 1] >> 4);
            A[Length - 1] = (A[Length - 1] << 4) | ich;
        }
    else
        return 0;

    return 1;
}
