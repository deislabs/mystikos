#include <signal.h>
#include <errno.h>

int sigprocmask(int how, const sigset_t *restrict set, sigset_t *restrict old)
{
	int r = pthread_sigmask(how, set, old);
	if (!r) return r;
	errno = r;
	return -1;
}

static unsigned int sigset_to_int(const sigset_t *set)
{
  unsigned int ret = 0;
  if (sizeof(sigset_t) == sizeof(ret))
    return *(unsigned int*)set;

  for (unsigned sig = 1; sig < _NSIG && sig <= sizeof(ret) * 8; sig++) {
    if (sigismember (set, sig))
      ret |= (1u << ((sig) - 1));
  }
  return ret;
}

static void int_to_sigset(sigset_t *set, int sigs)
{
  if (sizeof(sigset_t) == sizeof(sigs))
    *(unsigned*)set = sigs;

  sigemptyset(set);
  for (unsigned sig = 1; sig < _NSIG && sig <= sizeof(sigs) * 8; sig++) {
    if (sigs & (1u << ((sig) - 1)))
      sigaddset(set, sig);
  }
}

int __sigsetmask (int mask)
{
  sigset_t set, old;
  
  int_to_sigset(&set, mask);

  if (sigprocmask (SIG_SETMASK, &set, &old) < 0)
    return -1;

  return sigset_to_int(&old);
}

weak_alias (__sigsetmask, sigsetmask);
