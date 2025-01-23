
__attribute__((__weak__))
int __popcountdi2(unsigned long a)
{
    unsigned long nbits = 0;

    /* Count the number of bits that are set */
    for (unsigned long i = 0; i < 64; i++)
    {
        if ((a & (1LU << i)))
            nbits++;
    }

    /* Return 1 if the nbits is odd; return 0 if nbits is event */
    return (nbits % 2) ? 1 : 0;
}
