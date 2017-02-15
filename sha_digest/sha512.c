/*
 *  This program implements the Secure Hashing Algorithm SHA512 as
 *  described in FIPS PUB 180-3 published in October 2008, see
 *
 *  http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf
 *
 *  PLEASE NOTE: While I implemented the SHA512 algorithm as good as my
 *               abilities and understanding of the standard cited above
 *               allow I'm not claiming that it is error free. Thus if
 *               you intend to use it e.g. in cryptographic applications
 *               you must review and test it carefully yourself!
 *
 *  A lot of ideas came from the example implementation from RFC 3174
 *  by D. Eastlake, 3rd (Motorola) and P. Jones (Cisco Systems), see
 *  e.g.
 *
 *  http://www.faqs.org/rfcs/rfc3174.html
 *
 *  The part for dealing with 64-bit numbers on systems that lack such
 *  a type has directly been taken from code written by Paul Eggert,
 *  and which is part of the GNU Coreutils in the file 'lib/u64.h'
 *  and can be downloaded e.g. from
 *
 *  http://www.gnu.org/software/coreutils/
 *
 *  What of the rest may be new is
 *
 *  Copyright (C) 2009 Jens Thoms Toerring <jt@toerring.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with fsc2.  If not, see <http://www.gnu.org/licenses/>.
 */

#define NEED_U64_SET
#define NEED_U64_PLUS
#define NEED_U64_LOW
#define NEED_U64_HI
#define NEED_U64_INV
#define NEED_U64_AND
#define NEED_U64_OR
#define NEED_U64_XOR
#define NEED_U64_SHL
#define NEED_U64_SHR
#define NEED_U128_SET
#define NEED_U128_LT
#define NEED_U128_PLUS
#define NEED_U128_SIZET_PLUS
#define NEED_U128_LOW
#define NEED_U128_SHR

#include "sha512.h"


/* Circular right rotation of 64-bit value 'val' left by 'bits' bits */

#define ROTR( bits, val )                                   \
        ( sha_u64_or( sha_u64_shr( val, bits ),             \
                      sha_u64_shl( val, 64 - ( bits ) ) ) )


/* Right shift of 64-bit value 'val' left by 'bits' bits */

#define SHR( bits, val )  ( sha_u64_shr( val, bits ) )


/* Initial hash values (see p. 15 and 16 of FIPS 180-3), split up into
   32-bit values */

static const sha_u32 H[ 8 ][ 2 ] = { { 0x6a09e667, 0xf3bcc908 },
                                     { 0xbb67ae85, 0x84caa73b },
                                     { 0x3c6ef372, 0xfe94f82b },
                                     { 0xa54ff53a, 0x5f1d36f1 },
                                     { 0x510e527f, 0xade682d1 },
                                     { 0x9b05688c, 0x2b3e6c1f },
                                     { 0x1f83d9ab, 0xfb41bd6b },
                                     { 0x5be0cd19, 0x137e2179 } };

/* Constants required for hash calculation (see p. 11 and 12 of FIPS 180-3),
   split up into 32-bit values */

static sha_u64 K[ 80 ];
static const sha_u32 K2[ 80 ][ 2 ] = { { 0x428a2f98, 0xd728ae22 },
                                       { 0x71374491, 0x23ef65cd },
                                       { 0xb5c0fbcf, 0xec4d3b2f },
                                       { 0xe9b5dba5, 0x8189dbbc },
                                       { 0x3956c25b, 0xf348b538 },
                                       { 0x59f111f1, 0xb605d019 },
                                       { 0x923f82a4, 0xaf194f9b },
                                       { 0xab1c5ed5, 0xda6d8118 },
                                       { 0xd807aa98, 0xa3030242 },
                                       { 0x12835b01, 0x45706fbe },
                                       { 0x243185be, 0x4ee4b28c },
                                       { 0x550c7dc3, 0xd5ffb4e2 },
                                       { 0x72be5d74, 0xf27b896f },
                                       { 0x80deb1fe, 0x3b1696b1 },
                                       { 0x9bdc06a7, 0x25c71235 },
                                       { 0xc19bf174, 0xcf692694 },
                                       { 0xe49b69c1, 0x9ef14ad2 },
                                       { 0xefbe4786, 0x384f25e3 },
                                       { 0x0fc19dc6, 0x8b8cd5b5 },
                                       { 0x240ca1cc, 0x77ac9c65 },
                                       { 0x2de92c6f, 0x592b0275 },
                                       { 0x4a7484aa, 0x6ea6e483 },
                                       { 0x5cb0a9dc, 0xbd41fbd4 },
                                       { 0x76f988da, 0x831153b5 },
                                       { 0x983e5152, 0xee66dfab },
                                       { 0xa831c66d, 0x2db43210 },
                                       { 0xb00327c8, 0x98fb213f },
                                       { 0xbf597fc7, 0xbeef0ee4 },
                                       { 0xc6e00bf3, 0x3da88fc2 },
                                       { 0xd5a79147, 0x930aa725 },
                                       { 0x06ca6351, 0xe003826f },
                                       { 0x14292967, 0x0a0e6e70 },
                                       { 0x27b70a85, 0x46d22ffc },
                                       { 0x2e1b2138, 0x5c26c926 },
                                       { 0x4d2c6dfc, 0x5ac42aed },
                                       { 0x53380d13, 0x9d95b3df },
                                       { 0x650a7354, 0x8baf63de },
                                       { 0x766a0abb, 0x3c77b2a8 },
                                       { 0x81c2c92e, 0x47edaee6 },
                                       { 0x92722c85, 0x1482353b },
                                       { 0xa2bfe8a1, 0x4cf10364 },
                                       { 0xa81a664b, 0xbc423001 },
                                       { 0xc24b8b70, 0xd0f89791 },
                                       { 0xc76c51a3, 0x0654be30 },
                                       { 0xd192e819, 0xd6ef5218 },
                                       { 0xd6990624, 0x5565a910 },
                                       { 0xf40e3585, 0x5771202a },
                                       { 0x106aa070, 0x32bbd1b8 },
                                       { 0x19a4c116, 0xb8d2d0c8 },
                                       { 0x1e376c08, 0x5141ab53 },
                                       { 0x2748774c, 0xdf8eeb99 },
                                       { 0x34b0bcb5, 0xe19b48a8 },
                                       { 0x391c0cb3, 0xc5c95a63 },
                                       { 0x4ed8aa4a, 0xe3418acb },
                                       { 0x5b9cca4f, 0x7763e373 },
                                       { 0x682e6ff3, 0xd6b2b8a3 },
                                       { 0x748f82ee, 0x5defb2fc },
                                       { 0x78a5636f, 0x43172f60 },
                                       { 0x84c87814, 0xa1f0ab72 },
                                       { 0x8cc70208, 0x1a6439ec },
                                       { 0x90befffa, 0x23631e28 },
                                       { 0xa4506ceb, 0xde82bde9 },
                                       { 0xbef9a3f7, 0xb2c67915 },
                                       { 0xc67178f2, 0xe372532b },
                                       { 0xca273ece, 0xea26619c },
                                       { 0xd186b8c7, 0x21c0c207 },
                                       { 0xeada7dd6, 0xcde0eb1e },
                                       { 0xf57d4f7f, 0xee6ed178 },
                                       { 0x06f067aa, 0x72176fba },
                                       { 0x0a637dc5, 0xa2c898a6 },
                                       { 0x113f9804, 0xbef90dae },
                                       { 0x1b710b35, 0x131c471b },
                                       { 0x28db77f5, 0x23047d84 },
                                       { 0x32caab7b, 0x40c72493 },
                                       { 0x3c9ebe0a, 0x15c9bebc },
                                       { 0x431d67c4, 0x9c100d4c },
                                       { 0x4cc5d4be, 0xcb3e42b6 },
                                       { 0x597f299c, 0xfc657e2a },
                                       { 0x5fcb6fab, 0x3ad6faec },
                                       { 0x6c44198c, 0x4a475817 } };


/* Local functions */

static void sha512_process_block( SHA512_Context * context );
static void sha512_evaluate( SHA512_Context * context );


/*----------------------------------------------------------------*
 * Sets up the context structure (or resets it) and the array 'K'
 * used in the hash calculation
 *----------------------------------------------------------------*/

int
sha512_initialize( SHA512_Context * context )
{
    static unsigned char K_is_set = 0;
    size_t i;


    if ( ! context )
        return SHA_DIGEST_INVALID_ARG;

    for ( i = 0; i < 8; i++ )
        context->H[ i ] = sha_u64_set( H[ i ][ 0 ], H[ i ][ 1 ] );

    if ( ! K_is_set )
    {
        for ( i = 0; i < 80; i++ )
            K[ i ] = sha_u64_set( K2[ i ][ 0 ], K2[ i ][ 1 ] );
        K_is_set = 1;
    }

    context->count         = sha_u128_set( 0, 0, 0, 0 );
    context->off_count     = 0;
    context->index         = 0;
    context->is_calculated = 0;
    context->error         = SHA_DIGEST_OK;

    return SHA_DIGEST_OK;
}


/*----------------------------------------------------------------*
 * Adds byte-oriented data for the calculation of the hash
 *----------------------------------------------------------------*/

int
sha512_add_bytes( SHA512_Context * context,
                  const void     * data,
                  size_t           num_bytes )
{
    /* If necessary use bit-oriented routine */

    if ( context->off_count != 0 )
        return sha512_add_bits( context, data, 8 * num_bytes );

    if ( ! context || ! data )
        return SHA_DIGEST_INVALID_ARG;

    if ( context->error )
        return context->error;

    if ( context->is_calculated )
        return context->error = SHA_DIGEST_NO_MORE_DATA;

    /* Split up the input into 1024 bit sized chunks from which the hash
       value gets calculated */

    while ( num_bytes )
    {
        unsigned int len = num_bytes >= 128 ? 128 : num_bytes;

        if ( context->index + len > 128 )
            len = 128 - context->index;

        /* Increment bit count, abort on input of more than 2^64 bits */

        context->count = sha_u128_plus( context->count,
                                        sha_u128_set( 0, 0, 0, 8 * len ) );
        if ( sha_u128_lt( context->count, sha_u128_set( 0, 0, 0, 8 * len ) ) )
            return context->error = SHA_DIGEST_INPUT_TOO_LONG;

        memcpy( context->buf + context->index, data, len );
        data       = ( unsigned char * ) data + len;
        num_bytes -= len;

        if ( ( context->index += len ) == 128 )
            sha512_process_block( context );
    }

    return SHA_DIGEST_OK;
}


/*----------------------------------------------------------------*
 * Adds bit-oriented data for the calculation of the hash
 *----------------------------------------------------------------*/

int
sha512_add_bits( SHA512_Context * context,
                 const void     * data,
                 size_t           num_bits )
{
    const unsigned char *d = data;
    unsigned char shift = 8 - context->off_count;


    /* Always try to use the byte-oriented routine as far as possible */

    if ( context->off_count == 0 && num_bits > 7 )
    {
        int ret = sha512_add_bytes( context, data, num_bits / 8 );

        d += num_bits / 8;

        if ( ( num_bits &= 0x07 ) == 0 || ret != SHA_DIGEST_OK )
            return ret;
    }
    else
    {
        if ( ! context || ! data )
            return SHA_DIGEST_INVALID_ARG;

        if ( context->error )
            return context->error;

        if ( context->is_calculated )
            return context->error = SHA_DIGEST_NO_MORE_DATA;
    }

    if ( num_bits == 0 )
        return SHA_DIGEST_OK;

    /* Increment bit count, abort on input of 2^128 or more bits (note:
       sha_u128_sizet_add() returns a 0 value on overflow!) */

    context->count = sha_u128_sizet_plus( context->count, num_bits );
    if ( sha_u128_eq( context->count, sha_u128_set( 0, 0, 0, 0 ) ) )
        return context->error = SHA_DIGEST_INPUT_TOO_LONG;

    /* Deal with all full (8-bit) bytes of input */

    while ( num_bits > 7 )
    {
        context->buf[ context->index++ ] |= SHA_T8( *d ) >> context->off_count;
        context->buf[ context->index   ]  = *d++ << shift;
        num_bits -= 8;

        if ( context->index == 128 )
        {
            sha512_process_block( context );
            context->buf[ 0 ] = context->buf[ 128 ];
        }
    }

    /* Now we're left with no more that 7 bits, they may or may not fit into
       the current byte of the context's buffer */

    if ( num_bits > 0 )
    {
        if ( num_bits <= shift )
        {
            if ( context->off_count == 0 )
                context->buf[ context->index ] = 0;

            context->buf[ context->index ] |=
                  ( SHA_T8( *d ) >> ( 8 - num_bits ) ) << ( shift - num_bits );

            if ( ( context->off_count += num_bits ) == 8 )
            {
                context->off_count = 0;
                if ( ++context->index == 128 )
                    sha512_process_block( context );
            }
        }
        else
        {
            context->buf[ context->index++ ] |=
                                            SHA_T8( *d ) >> context->off_count;
            context->buf[ context->index   ]  = *d << shift;

            context->off_count = ( context->off_count + num_bits ) % 8;

            if ( context->index == 128 )
            {
                sha512_process_block( context );
                context->buf[ 0 ] = context->buf[ 128 ];
            }
        }
    }

    return SHA_DIGEST_OK;
}


/*----------------------------------------------------------------*
 * If the digest hadn't been calculated before finalize the
 * calculation, then copy the result iver to the use supplied
 * buffer.
 *----------------------------------------------------------------*/

int
sha512_calculate( SHA512_Context  * context,
                  unsigned char   digest[ SHA512_HASH_SIZE ] )
{
    size_t i,
           j;


    if ( ! context || ! digest )
        return SHA_DIGEST_INVALID_ARG;

    if ( context->error )
        return context->error;

    if ( ! context->is_calculated )
        sha512_evaluate( context );

    for ( i = j = 0; j < SHA512_HASH_SIZE; i++ )
    {
        digest[ j++ ] = sha_u64_hi(  context->H[ i ] ) >> 24;
        digest[ j++ ] = sha_u64_hi(  context->H[ i ] ) >> 16;
        digest[ j++ ] = sha_u64_hi(  context->H[ i ] ) >>  8;
        digest[ j++ ] = sha_u64_hi(  context->H[ i ] );
        digest[ j++ ] = sha_u64_low( context->H[ i ] ) >> 24;
        digest[ j++ ] = sha_u64_low( context->H[ i ] ) >> 16;
        digest[ j++ ] = sha_u64_low( context->H[ i ] ) >>  8;
        digest[ j++ ] = sha_u64_low( context->H[ i ] );
    }

    return SHA_DIGEST_OK;
}


/*----------------------------------------------------------------*
 * Central routine for calculating the hash value. See the FIPS
 * 180-3 standard p. 24 for a detailed explanation.
 *----------------------------------------------------------------*/

#define Ch    sha_u64_xor( sha_u64_and( E, F ),                  \
                           sha_u64_and( sha_u64_inv( E ), G ) )

#define Maj   sha_u64_xor(              sha_u64_and( B, C ),     \
                           sha_u64_xor( sha_u64_and( B, D ),     \
                                        sha_u64_and( C, D ) ) )

#define Sig0  sha_u64_xor(              ROTR( 28, B ),    \
                           sha_u64_xor( ROTR( 34, B ),    \
                                        ROTR( 39, B ) ) )

#define Sig1  sha_u64_xor(              ROTR( 14, E ),     \
                           sha_u64_xor( ROTR( 18, E ),     \
                                        ROTR( 41, E ) ) )

#define sig0( x )  sha_u64_xor( ROTR(  1, x ),                               \
                                sha_u64_xor( ROTR(  8, x ), SHR( 7, x ) ) )

#define sig1( x )  sha_u64_xor( ROTR( 19, x ),                               \
                                sha_u64_xor( ROTR( 61, x ), SHR( 6, x ) ) )

static void
sha512_process_block( SHA512_Context * context )
{
    size_t         t;
    sha_u64        W[ 80 ];
    sha_u64        A, B, C, D, E, F, G, H, tmp;
    unsigned char *buf = context->buf;


    A = context->H[ 0 ];
    B = context->H[ 1 ];
    C = context->H[ 2 ];
    D = context->H[ 3 ];
    E = context->H[ 4 ];
    F = context->H[ 5 ];
    G = context->H[ 6 ];
    H = context->H[ 7 ];

    for ( t = 0; t < 16; buf += 8, t++ )
    {
        W[ t ] = sha_u64_set(   SHA_T8L( buf[ 0 ] ) << 24
                              | SHA_T8L( buf[ 1 ] ) << 16
                              | SHA_T8L( buf[ 2 ] ) <<  8
                              | SHA_T8L( buf[ 3 ] ),
                                SHA_T8L( buf[ 4 ] ) << 24
                              | SHA_T8L( buf[ 5 ] ) << 16
                              | SHA_T8L( buf[ 6 ] ) <<  8
                              | SHA_T8L( buf[ 7 ] ) );

        tmp = sha_u64_plus( H,
                  sha_u64_plus( Sig1,
                      sha_u64_plus( Ch,
                          sha_u64_plus( K[ t ], W[ t ] ) ) ) );
        H = G;
        G = F;
        F = E;
        E = sha_u64_plus( D, tmp );
        D = C;
        C = B;
        B = A;
        A = sha_u64_plus( tmp, sha_u64_plus( Sig0, Maj ) );
    }

    for ( ; t < 80; t++ )
    {
        W[ t ] = sha_u64_plus( sig1( W[ t -  2 ] ),
                     sha_u64_plus( W[ t -  7 ],
                         sha_u64_plus( sig0( W[ t - 15 ] ), W[ t - 16 ] ) ) );

        tmp = sha_u64_plus( H,
                  sha_u64_plus( Sig1,
                      sha_u64_plus( Ch,
                          sha_u64_plus( K[ t ], W[ t ] ) ) ) );
        H = G;
        G = F;
        F = E;
        E = sha_u64_plus( D, tmp );
        D = C;
        C = B;
        B = A;
        A = sha_u64_plus( tmp, sha_u64_plus( Sig0, Maj ) );
    }

    context->H[ 0 ] = sha_u64_plus( context->H[ 0 ], A );
    context->H[ 1 ] = sha_u64_plus( context->H[ 1 ], B );
    context->H[ 2 ] = sha_u64_plus( context->H[ 2 ], C );
    context->H[ 3 ] = sha_u64_plus( context->H[ 3 ], D );
    context->H[ 4 ] = sha_u64_plus( context->H[ 4 ], E );
    context->H[ 5 ] = sha_u64_plus( context->H[ 5 ], F );
    context->H[ 6 ] = sha_u64_plus( context->H[ 6 ], G );
    context->H[ 7 ] = sha_u64_plus( context->H[ 7 ], H );

    context->index = 0;
}


/*----------------------------------------------------------------*
 * To be called when all data have been entered, applies padding
 * and does the final round of the calculation.
 *----------------------------------------------------------------*/

static void
sha512_evaluate( SHA512_Context * context )
{
    int      i;
    sha_u128 count;


    /* If the block is too short for padding (at least one bit plus the
     * bit count as a 128-bit number) padd to the end of the block with 0
     * and then start a new block that contains just 0 and the bit count. */

    if ( context->off_count == 0 )
        context->buf[ context->index++ ] = 0x80;
    else
        context->buf[ context->index++ ] |= 0x80 >> context->off_count;

    if ( context->index > 112 )
    {
        memset( context->buf + context->index, 0, 128 - context->index );
        sha512_process_block( context );
        memset( context->buf, 0, 112 );
    }
    else
        memset( context->buf + context->index, 0, 112 - context->index );

    /* Store bit count at end and do the final round of the calculation */

    for ( count = context->count, i = 127; i > 111;
          count = sha_u128_shr( count, 8 ), i-- )
        context->buf[ i ] = sha_u128_low( count );

    sha512_process_block( context );
    context->is_calculated = 1;

    /* Wipe memory used for storing data supplied by user */

    memset( context->buf, 0, sizeof context->buf );
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
