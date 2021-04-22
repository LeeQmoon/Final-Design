#include<sys/time.h>
#include<fcntl.h>
#include<stdio.h>
#include"type.h"

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif
#define __bitwise __bitwise__
typedef u32 __bitwise __be32;
typedef unsigned short u16;
typedef u16 __bitwise __be16;
# define __force	__attribute__((force))

static unsigned int random_val;

static inline u_int32 rol32(u_int32 word, unsigned int shift)
{
	return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static inline u_int32 __jhash_nwords(u_int32 a, u_int32 b, u_int32 c, u_int32 initval)
{
	a += initval;
	b += initval;
	c += initval;

	__jhash_final(a, b, c);

	return c;
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL		0xdeadbeef
static inline u32 jhash_3words(u_int32 a, u_int32 b, u_int32 c, u_int32 initval)
{
	return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

static inline unsigned int __inet_ehashfn(const u_int32 laddr,
					  const u_int16 lport,
					  const u_int32 faddr,
					  const u_int16 fport,
					  u_int32 initval)
{
	return jhash_3words((__force u32) laddr,
			    (__force u32) faddr,
			    ((u32) lport) << 16 | (__force u32)fport,
			    initval);
}

static u32 inet_ehashfn(const __be32 laddr,
			const u16 lport, const __be32 faddr,
			const __be16 fport)
{
    
	//static u32 inet_ehash_secret = rand();

	//net_get_random_once(&inet_ehash_secret, sizeof(inet_ehash_secret));

	return __inet_ehashfn(laddr, lport, faddr, fport,
			      random_val);
}

void initRandom() {
    struct timeval s;
    gettimeofday(&s, 0);    //不用time(),time返回秒精度,在1s内多次调用,数据会一样
    srand(s.tv_usec); 
    random_val = rand();
}




