/*
 *  This is an example of how a program that uses the SHA algorithms could
 *  be written. What algorithm gets used depends on the name the program
 *  is invoked as (via symbolic links). It reads data either from a file
 *  if one is given as a command line argument, or otherwise from stdin.
 *
 *  This program hasn't been optimized for speed, instead it is supposed
 *  to be platform independent and C89 compliant.
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


#include <stdio.h>
#include <stdlib.h>
#include <sha_digest.h>


#define BUF_SIZE  16384


typedef struct {
    int ( * init )( );
    int ( * add  )( );
    int ( * calc )( );
    union {
        SHA1_Context   sha1;
        SHA224_Context sha224;
        SHA256_Context sha256;
        SHA384_Context sha384;
        SHA512_Context sha512;
    } context;
    size_t hashlen;
} sha_t;


/*---------------------------------------------------------------*
 *---------------------------------------------------------------*/

static void
usage( const char *pn )
{
    if ( ! strcmp( pn, "sha1_digest" ) )
        fprintf( stderr, "Usage: sha1_digest [FILE]\n"
                 "Print SHA-1 (160-bit) digest of byte-oriented input.\n" );
    else if ( ! strcmp( pn, "sha224_digest" ) )
        fprintf( stderr, "Usage: sha224_digest [FILE]\n"
                 "Print SHA-224 (224-bit) digest of byte-oriented input.\n" );
    else if ( ! strcmp( pn, "sha256_digest" ) )
        fprintf( stderr, "Usage: sha256_digest [FILE]\n"
                 "Print SHA-256 (256-bit) digest of byte-oriented input.\n" );
    else if ( ! strcmp( pn, "sha384_digest" ) )
        fprintf( stderr, "Usage: sha384_digest [FILE]\n"
                 "Print SHA-384 (384-bit) digest of byte-oriented input.\n"  );
    else if ( ! strcmp( pn, "sha512_digest" ) )
        fprintf( stderr, "Usage: sha512_digest [FILE]\n"
                 "Print SHA-512 (512-bit) digest of byte-oriented input.\n"  );
    else
        fprintf( stderr, "Usage: sha_digest SHA-TYPE [FILE]\n"
                 "Print SHA digest of byte-oriented input.\n"
                 "For SHA-TYPE use\n"
                 "  -sha1      print SHA-1 (160-bit) digest\n"
                 "  -sha224    print SHA-224 (224-bit) digest\n"
                 "  -sha256    print SHA-256 (256-bit) digest\n"
                 "  -sha384    print SHA-384 (384-bit) digest\n"
                 "  -sha512    print SHA-512 (512-bit) digest\n" );
    fprintf( stderr,
             "With no FILE (or when FILE is -) read standard input.\n" );

    exit( EXIT_FAILURE );
}


/*---------------------------------------------------------------*
 *---------------------------------------------------------------*/

static void
set_funcs( sha_t      * sha,
           int          what,
           const char * pn )
{
    switch ( what )
    {
        case 1 :
            sha->init    = sha1_initialize;
            sha->add     = sha1_add_bytes;
            sha->calc    = sha1_calculate;
            sha->hashlen = SHA1_HASH_SIZE;
            break;

        case 224 :
            sha->init    = sha224_initialize;
            sha->add     = sha224_add_bytes;
            sha->calc    = sha224_calculate;
            sha->hashlen = SHA224_HASH_SIZE;
            break;

        case 256 :
            sha->init    = sha256_initialize;
            sha->add     = sha256_add_bytes;
            sha->calc    = sha256_calculate;
            sha->hashlen = SHA256_HASH_SIZE;
            break;

        case 384 :
            sha->init    = sha384_initialize;
            sha->add     = sha384_add_bytes;
            sha->calc    = sha384_calculate;
            sha->hashlen = SHA384_HASH_SIZE;
            break;

        case 512 :
            sha->init    = sha512_initialize;
            sha->add     = sha512_add_bytes;
            sha->calc    = sha512_calculate;
            sha->hashlen = SHA512_HASH_SIZE;
            break;

        default :
            usage( pn );
    }
}


/*---------------------------------------------------------------*
 *---------------------------------------------------------------*/

static FILE *
get_opts( sha_t *  sha,
          char  ** argv )
{
    FILE *fp;
    char *arg = strrchr( argv[ 0 ], '/' );


    if ( ! arg )
        arg = argv[ 0 ];
    else
        arg++;

    if ( ! strcmp( arg, "sha1_digest" ) )
        set_funcs( sha, 1, arg );
    else if ( ! strcmp( arg, "sha224_digest" ) )
        set_funcs( sha, 224, arg );
    else if ( ! strcmp( arg, "sha256_digest" ) )
        set_funcs( sha, 256, arg );
    else if ( ! strcmp( arg, "sha384_digest" ) )
        set_funcs( sha, 384, arg );
    else if ( ! strcmp( arg, "sha512_digest" ) )
        set_funcs( sha, 512, arg );
    else if ( ! strcmp( arg, "sha_digest" ) )
    {
        if ( ! argv[ 1 ] )
            usage( arg );
        else if ( ! strcmp( argv[ 1 ], "-sha1" ) )
            set_funcs( sha, 1, arg );
        else if ( ! strcmp( argv[ 1 ], "-sha224" ) )
            set_funcs( sha, 224, arg );
        else if ( ! strcmp( argv[ 1 ], "-sha256" ) )
            set_funcs( sha, 256, arg );
        else if ( ! strcmp( argv[ 1 ], "-sha384" ) )
            set_funcs( sha, 384, arg );
        else if ( ! strcmp( argv[ 1 ], "-sha512" ) )
            set_funcs( sha, 512, arg );
        else
            usage( arg );
        argv++;
    }
    else
        usage( arg );

    if ( ! argv[ 1 ] || ! strcmp( argv[ 1 ], "-" ) ) 
        return stdin;

    if ( ( fp = fopen( argv[ 1 ], "rb" ) ) == NULL )
    {
        fprintf( stderr, "Can't open file %s for reading.\n", argv[ 1 ] );
        exit( EXIT_FAILURE );
    }

    return fp;
}


/*---------------------------------------------------------------*
 *---------------------------------------------------------------*/

int
main( int     argc,
      char ** argv )
{
    FILE *fp;
    unsigned char buf[ BUF_SIZE ];
    size_t count;
    sha_t sha;
    unsigned char digest[ SHA512_HASH_SIZE ];  /* SHA512 has longest digest */
    size_t i;
    char * arg = strrchr( argv[ 0 ], '/' );

    if (    argc > 1
         && ( ! strcmp( argv[ 1 ], "-h" ) || ! strcmp( argv[ 1 ], "--help" ) ) )
        usage( arg ? arg + 1 : argv[ 0 ] );

    fp = get_opts( &sha, argv );

    if ( sha.init( &sha.context ) != SHA_DIGEST_OK )
    {
        fclose( fp );
        fprintf( stderr, "Failed to initialize SHA library.\n" );
        return EXIT_FAILURE;
    }

    while ( ( count = fread( buf, 1, BUF_SIZE, fp ) ) > 0 )
        if ( sha.add( &sha.context, buf, count ) != SHA_DIGEST_OK )
        {
            fclose( fp );
            fprintf( stderr, "Failed to pass data for SHA digest.\n" );
            return EXIT_FAILURE;
        }

    fclose( fp );

    if ( sha.calc( &sha.context, digest ) != SHA_DIGEST_OK )
    {
        fprintf( stderr, "Failed to calculate digest.\n" );
        return EXIT_FAILURE;
    }

    for ( i = 0; i < sha.hashlen; i++ )
        printf( "%02x", digest[ i ] );
    puts( "" );

    return EXIT_SUCCESS;
}


/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
