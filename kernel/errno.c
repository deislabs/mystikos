#include <stddef.h>
#include <stdio.h>
#include <libos/errno.h>

typedef struct pair
{
    long errnum;
    const char* errstr;
}
pair_t;

static pair_t _pairs[] =
{
    { EPERM, "EPERM" },
    { ENOENT, "ENOENT" },
    { ESRCH, "ESRCH" },
    { EINTR, "EINTR" },
    { EIO, "EIO" },
    { ENXIO, "ENXIO" },
    { E2BIG, "E2BIG" },
    { ENOEXEC, "ENOEXEC" },
    { EBADF, "EBADF" },
    { ECHILD, "ECHILD" },
    { EAGAIN, "EAGAIN" },
    { ENOMEM, "ENOMEM" },
    { EACCES, "EACCES" },
    { EFAULT, "EFAULT" },
    { ENOTBLK, "ENOTBLK" },
    { EBUSY, "EBUSY" },
    { EEXIST, "EEXIST" },
    { EXDEV, "EXDEV" },
    { ENODEV, "ENODEV" },
    { ENOTDIR, "ENOTDIR" },
    { EISDIR, "EISDIR" },
    { EINVAL, "EINVAL" },
    { ENFILE, "ENFILE" },
    { EMFILE, "EMFILE" },
    { ENOTTY, "ENOTTY" },
    { ETXTBSY, "ETXTBSY" },
    { EFBIG, "EFBIG" },
    { ENOSPC, "ENOSPC" },
    { ESPIPE, "ESPIPE" },
    { EROFS, "EROFS" },
    { EMLINK, "EMLINK" },
    { EPIPE, "EPIPE" },
    { EDOM, "EDOM" },
    { ERANGE, "ERANGE" },
    { EDEADLK, "EDEADLK" },
    { ENAMETOOLONG, "ENAMETOOLONG" },
    { ENOLCK, "ENOLCK" },
    { ENOSYS, "ENOSYS" },
    { ENOTEMPTY, "ENOTEMPTY" },
    { ELOOP, "ELOOP" },
    { EWOULDBLOCK, "EWOULDBLOCK" },
    { ENOMSG, "ENOMSG" },
    { EIDRM, "EIDRM" },
    { ECHRNG, "ECHRNG" },
    { EL2NSYNC, "EL2NSYNC" },
    { EL3HLT, "EL3HLT" },
    { EL3RST, "EL3RST" },
    { ELNRNG, "ELNRNG" },
    { EUNATCH, "EUNATCH" },
    { ENOCSI, "ENOCSI" },
    { EL2HLT, "EL2HLT" },
    { EBADE, "EBADE" },
    { EBADR, "EBADR" },
    { EXFULL, "EXFULL" },
    { ENOANO, "ENOANO" },
    { EBADRQC, "EBADRQC" },
    { EBADSLT, "EBADSLT" },
    { EDEADLOCK, "EDEADLOCK" },
    { EBFONT, "EBFONT" },
    { ENOSTR, "ENOSTR" },
    { ENODATA, "ENODATA" },
    { ETIME, "ETIME" },
    { ENOSR, "ENOSR" },
    { ENONET, "ENONET" },
    { ENOPKG, "ENOPKG" },
    { EREMOTE, "EREMOTE" },
    { ENOLINK, "ENOLINK" },
    { EADV, "EADV" },
    { ESRMNT, "ESRMNT" },
    { ECOMM, "ECOMM" },
    { EPROTO, "EPROTO" },
    { EMULTIHOP, "EMULTIHOP" },
    { EDOTDOT, "EDOTDOT" },
    { EBADMSG, "EBADMSG" },
    { EOVERFLOW, "EOVERFLOW" },
    { ENOTUNIQ, "ENOTUNIQ" },
    { EBADFD, "EBADFD" },
    { EREMCHG, "EREMCHG" },
    { ELIBACC, "ELIBACC" },
    { ELIBBAD, "ELIBBAD" },
    { ELIBSCN, "ELIBSCN" },
    { ELIBMAX, "ELIBMAX" },
    { ELIBEXEC, "ELIBEXEC" },
    { EILSEQ, "EILSEQ" },
    { ERESTART, "ERESTART" },
    { ESTRPIPE, "ESTRPIPE" },
    { EUSERS, "EUSERS" },
    { ENOTSOCK, "ENOTSOCK" },
    { EDESTADDRREQ, "EDESTADDRREQ" },
    { EMSGSIZE, "EMSGSIZE" },
    { EPROTOTYPE, "EPROTOTYPE" },
    { ENOPROTOOPT, "ENOPROTOOPT" },
    { EPROTONOSUPPORT, "EPROTONOSUPPORT" },
    { ESOCKTNOSUPPORT, "ESOCKTNOSUPPORT" },
    { EOPNOTSUPP, "EOPNOTSUPP" },
    { ENOTSUP, "ENOTSUP" },
    { EPFNOSUPPORT, "EPFNOSUPPORT" },
    { EAFNOSUPPORT, "EAFNOSUPPORT" },
    { EADDRINUSE, "EADDRINUSE" },
    { EADDRNOTAVAIL, "EADDRNOTAVAIL" },
    { ENETDOWN, "ENETDOWN" },
    { ENETUNREACH, "ENETUNREACH" },
    { ENETRESET, "ENETRESET" },
    { ECONNABORTED, "ECONNABORTED" },
    { ECONNRESET, "ECONNRESET" },
    { ENOBUFS, "ENOBUFS" },
    { EISCONN, "EISCONN" },
    { ENOTCONN, "ENOTCONN" },
    { ESHUTDOWN, "ESHUTDOWN" },
    { ETOOMANYREFS, "ETOOMANYREFS" },
    { ETIMEDOUT, "ETIMEDOUT" },
    { ECONNREFUSED, "ECONNREFUSED" },
    { EHOSTDOWN, "EHOSTDOWN" },
    { EHOSTUNREACH, "EHOSTUNREACH" },
    { EALREADY, "EALREADY" },
    { EINPROGRESS, "EINPROGRESS" },
    { ESTALE, "ESTALE" },
    { EUCLEAN, "EUCLEAN" },
    { ENOTNAM, "ENOTNAM" },
    { ENAVAIL, "ENAVAIL" },
    { EISNAM, "EISNAM" },
    { EREMOTEIO, "EREMOTEIO" },
    { EDQUOT, "EDQUOT" },
    { ENOMEDIUM, "ENOMEDIUM" },
    { EMEDIUMTYPE, "EMEDIUMTYPE" },
    { ECANCELED, "ECANCELED" },
    { ENOKEY, "ENOKEY" },
    { EKEYEXPIRED, "EKEYEXPIRED" },
    { EKEYREVOKED, "EKEYREVOKED" },
    { EKEYREJECTED, "EKEYREJECTED" },
    { EOWNERDEAD, "EOWNERDEAD" },
    { ENOTRECOVERABLE, "ENOTRECOVERABLE" },
    { ERFKILL, "ERFKILL" },
    { EHWPOISON, "EHWPOISON" },
};

static size_t _npairs = sizeof(_pairs) / sizeof(_pairs[0]);

const char* libos_error_name(long errnum)
{
    for (size_t i = 0; i < _npairs; i++)
    {
        if (_pairs[i].errnum == errnum)
            return _pairs[i].errstr;
    }

    return NULL;
}
