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

u32 inet_ehashfn(const __be32 laddr,
			const u16 lport, const __be32 faddr,
			const __be16 fport);

unsigned int __inet_ehashfn(const __be32 laddr,
					  const u16 lport,
					  const __be32 faddr,
					  const __be16 fport,
					  u32 initval)

                      u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval);

u32 __jhash_nwords(u32 a, u32 b, u32 c, u32 initval);
u32 rol32(u32 word, unsigned int shift);