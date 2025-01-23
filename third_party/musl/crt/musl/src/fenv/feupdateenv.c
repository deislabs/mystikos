#include <fenv.h>

int feupdateenv(const fenv_t *envp)
{
	int ex = fetestexcept(FE_ALL_EXCEPT);
	fesetenv(envp);
	feraiseexcept(ex);
	return 0;
}

int feenableexcept(int excepts)
{
	return 0;
}

int fedisableexcept(int excepts)
{
	return 0;
}
