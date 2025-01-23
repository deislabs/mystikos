__thread char      c1 = 1;
__thread char      xchar = 2;
__thread char      c2 = 3;
__thread short     xshort = 4;
__thread char      c3 = 5;
__thread int       xint = 6;
__thread char      c4 = 7;
__thread long long xllong = 8;

struct {
	char *name;
	unsigned size;
	unsigned align;
	unsigned long addr;
} t[4];

#define entry(i,x) \
	t[i].name = #x; \
	t[i].size = sizeof x; \
	t[i].align = __alignof__(x); \
	t[i].addr = (unsigned long)&x;

__attribute__((constructor)) static void init(void)
{
	entry(0, xchar)
	entry(1, xshort)
	entry(2, xint)
	entry(3, xllong)
}

