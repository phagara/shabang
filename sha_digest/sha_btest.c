#include <stdio.h>
#include <time.h>
#include <sha_digest.h>

#define BSIZE 131072

int
main( int    argc,
      char **argv )
{
    size_t rem, cur;
    size_t nbits, nbytes;
    unsigned char *buf, *lbuf;
    struct {
        int ( * init )( );
        int ( * add_bytes )( );
        int ( * add_bits )( );
        int ( * calc )( );
        union {
            SHA1_Context   sha1;
            SHA224_Context sha224;
            SHA256_Context sha256;
            SHA384_Context sha384;
            SHA512_Context sha512;
        } context;
        size_t hashlen;
    } sha;
    unsigned char digest[ SHA512_HASH_SIZE ];
    size_t i;
    FILE *fp;
    char *arg = strrchr( argv[ 0 ], '/' );
    char *eptr;


    srand( ( unsigned int ) time( NULL ) );


    if ( argc < 3 )
    {
        fprintf( stderr, "At least two arguments are needed, the number of\n"
                         "bits to be included into the hash and the number\n"
                         "of bytes in the input\n" );
        return EXIT_FAILURE;
    }

    if ( arg == 0 )
        arg = argv[ 0 ];
    else
        arg++;

    if ( ! strcmp( arg, "sha1_btest" ) )
    {
        sha.init      = sha1_initialize;
        sha.add_bytes = sha1_add_bytes;
        sha.add_bits  = sha1_add_bits;
        sha.calc      = sha1_calculate;
        sha.hashlen   = SHA1_HASH_SIZE;
    }
    else if ( ! strcmp( arg, "sha224_btest" ) )
    {
        sha.init      = sha224_initialize;
        sha.add_bytes = sha224_add_bytes;
        sha.add_bits  = sha224_add_bits;
        sha.calc      = sha224_calculate;
        sha.hashlen   = SHA224_HASH_SIZE;
    }
    else if ( ! strcmp( arg, "sha256_btest" ) )
    {
        sha.init      = sha256_initialize;
        sha.add_bytes = sha256_add_bytes;
        sha.add_bits  = sha256_add_bits;
        sha.calc      = sha256_calculate;
        sha.hashlen   = SHA256_HASH_SIZE;
    }
    else if ( ! strcmp( arg, "sha384_btest" ) )
    {
        sha.init      = sha384_initialize;
        sha.add_bytes = sha384_add_bytes;
        sha.add_bits  = sha384_add_bits;
        sha.calc      = sha384_calculate;
        sha.hashlen   = SHA384_HASH_SIZE;
    }
    else if ( ! strcmp( arg, "sha512_btest" ) )
    {
        sha.init      = sha512_initialize;
        sha.add_bytes = sha512_add_bytes;
        sha.add_bits  = sha512_add_bits;
        sha.calc      = sha512_calculate;
        sha.hashlen   = SHA512_HASH_SIZE;
    }
    else
    {
        fprintf( stderr, "Invalid invocation as '%s', it must be invoked\n"
                 "as 'shaX_digest' where X is 1, 224, 256, 284 or 512.\n",
                 arg );
        return EXIT_FAILURE;
    }

    nbits = strtoul( argv[ 1 ], &eptr, 10 );
    if ( argv[ 1 ][ 0 ] == '-' || *eptr != 0 )
    {
        fprintf( stderr, "Invalid number of bits to be hashed\n" );
        return EXIT_FAILURE;
    }

    nbytes = strtoul( argv[ 2 ], &eptr, 10 );
    if ( argv[ 2 ][ 0 ] == '-' || *eptr != 0 )
    {
        fprintf( stderr, "Invalid message kength (in bytes)\n" );
        return EXIT_FAILURE;
    }

    if ( nbits > 8 * nbytes )
    {
        fprintf( stderr, "Number of bits larger than message length\n" );
        return EXIT_FAILURE;
    }

    if ( argc == 3 )
        fp = stdin;
    else if ( ( fp = fopen( argv[ 3 ], "rb" ) ) == NULL )
    {
        fprintf( stderr, "Can't open file %s for reading.\n", argv[ 3 ] );
        return EXIT_FAILURE;
    }

    if ( ( lbuf = buf = malloc( nbytes ) ) == NULL )
    {
        fclose( fp );
        fprintf( stderr, "Not enough memory\n" );
        return EXIT_FAILURE;
    }

    if ( fread( buf, 1, nbytes, fp ) != nbytes )
    {
        free( buf );
        fclose( fp );
        fprintf( stderr, "Can't read %lu bytes from input\n",
                 ( unsigned long ) nbytes );
        return EXIT_FAILURE;
    }

    fclose( fp );

    if ( sha.init( &sha.context ) != SHA_DIGEST_OK )
    {
        free( buf );
        fprintf( stderr, "Failed to initialize SHA library\n" );
        return EXIT_FAILURE;
    }

    rem = nbits;

    while ( rem > 0 )
    {
        unsigned char s;

        while ( ( cur = rand( ) % 19 ) == 0 )
            /* empty */ ;

        if ( cur > rem )
            cur = rem;

        if ( sha.add_bits( &sha.context, lbuf, cur ) != SHA_DIGEST_OK )
        {
            free( buf );
            fprintf( stderr, "Failed to add bit-oriented data\n" );
            return EXIT_FAILURE;
        }

        lbuf += cur / 8;

        if ( ( rem -= cur ) > 0 && ( s = cur % 8 ) != 0 )
        {
            unsigned char *x = lbuf;

            for ( ; x < buf + nbytes - 1; x++ )
                *x = ( ( *x << s ) & 0xFF ) | ( *( x + 1 ) >> ( 8 - s ) );
            *x = *x << s;
        }
    }

    free( buf );

    if ( sha.calc( &sha.context, digest ) != SHA_DIGEST_OK )
    {
        fprintf( stderr, "Failed to calculate hash\n" );
        return EXIT_FAILURE;
    }

    for ( i = 0; i < sha.hashlen; i++ )
        printf( "%02x", digest[ i ] );
    puts( "" );

    return EXIT_SUCCESS;
}
