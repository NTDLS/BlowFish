#ifndef _BLOWFISH_CPP
#define _BLOWFISH_CPP
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "StdIO.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "BlowFish.H"
#include "SBoxes.H"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define N 16

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned long F(BlowFishCTX *ctx, unsigned long x)
{
    unsigned short a, b, c, d;
    unsigned long y;

    d = (unsigned short) x & 0x00FF;
    x >>= 8;
    c = (unsigned short) x & 0x00FF;
    x >>= 8;
    b = (unsigned short) x & 0x00FF;
    x >>= 8;
    a = (unsigned short) x & 0x00FF;

    y = ctx->S[0][a] + ctx->S[1][b];

    y = y ^ ctx->S[2][c];
    y = y + ctx->S[3][d];

    return y;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Blowfish_Encrypt(BlowFishCTX *ctx, unsigned long *xl, unsigned long *xr)
{
    unsigned long  Xl;
    unsigned long  Xr;
    unsigned long  temp;
    short       i;

    Xl = *xl;
    Xr = *xr;

    for (i = 0; i < N; ++i)
    {
        Xl = Xl ^ ctx->P[i];
        Xr = F(ctx, Xl) ^ Xr;
        temp = Xl;
        Xl = Xr;
        Xr = temp;
    }

    temp = Xl;
    Xl = Xr;
    Xr = temp;

    Xr = Xr ^ ctx->P[N];
    Xl = Xl ^ ctx->P[N + 1];

    *xl = Xl;
    *xr = Xr;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Blowfish_Decrypt(BlowFishCTX *ctx, unsigned long *xl, unsigned long *xr)
{
    unsigned long  Xl;
    unsigned long  Xr;
    unsigned long  temp;
    short       i;

    Xl = *xl;
    Xr = *xr;

    for (i = N + 1; i > 1; --i)
    {
        Xl = Xl ^ ctx->P[i];
        Xr = F(ctx, Xl) ^ Xr;

        // Exchange Xl and Xr
        temp = Xl;
        Xl = Xr;
        Xr = temp;
    }

    // Exchange Xl and Xr
    temp = Xl;
    Xl = Xr;
    Xr = temp;

    Xr = Xr ^ ctx->P[1];
    Xl = Xl ^ ctx->P[0];

    *xl = Xl;
    *xr = Xr;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Blowfish_Init(BlowFishCTX *ctx, unsigned char *key, int keyLen)
{
    int i, j, k;

    unsigned long data, datal, datar;

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 256; j++)
        {
            ctx->S[i][j] = ORIG_S[i][j];
        }
    }

    j = 0;

    for (i = 0; i < N + 2; ++i)
    {
        data = 0x00000000;
        for (k = 0; k < 4; ++k)
        {

            data <<= 8;
        	data |= (unsigned long) key[j] & 0xff;
            j = (j + 1);

            if (j >= keyLen)
            {
                j = 0;
            }
        }
        ctx->P[i] = ORIG_P[i] ^ data;
    }

    datal = 0x00000000;
    datar = 0x00000000;

    for (i = 0; i < N + 2; i += 2)
    {
        Blowfish_Encrypt(ctx, &datal, &datar);
        ctx->P[i] = datal;
        ctx->P[i + 1] = datar;
    }

    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 256; j += 2)
        {
            Blowfish_Encrypt(ctx, &datal, &datar);
            ctx->S[i][j] = datal;
            ctx->S[i][j + 1] = datar;
        }
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int Blowfish_Test(BlowFishCTX *ctx)
{
    unsigned long L = 1, R = 2;

    Blowfish_Init(ctx, (unsigned char*) "TESTKEY", 7);

    Blowfish_Encrypt(ctx, &L, &R);

    if(L != 0xDF333FD2L || R != 0x30A71BB4L)
        return 0;

    Blowfish_Decrypt(ctx, &L, &R);

    if(L != 1 || R != 2)
        return 0;

    return 1;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif

/*
void main(void)
{
    BlowFishCTX BlowFish;

    if(Blowfish_Test(&BlowFish))
        printf("Passed.\n");
    else printf("Failed.\n");
}
*/
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

