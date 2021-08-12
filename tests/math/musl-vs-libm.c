#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

double musl_sin(double);
double musl_cos(double);
double musl_tan(double);
double musl_asinh(double);
double musl_sinh(double);
double musl_acosh(double);

int eulp(double x)
{
    union {
        double f;
        uint64_t i;
    } u = {x};
    int e = u.i >> 52 & 0x7ff;

    if (!e)
        e++;
    return e - 0x3ff - 52;
}

/* Approximation */
float ulperr(double got, double want)
{
    if (isnan(got) && isnan(want))
        return 0;
    if (got == want)
    {
        if (signbit(got) == signbit(want))
            return 0;
        return INFINITY; // treat 0 sign errors badly
    }
    if (isinf(got))
    {
        got = copysign(0x1p1023, got);
        want *= 0.5;
    }
    return scalbn(got - want, -eulp(want));
}

int main()
{
    double x;
    size_t errcnt = 0;

    printf("\n============ Testing sin from 0 to 360 degrees ==============\n");
    for (int i = 0; i < 360; i++)
    {
        x = M_PI / 360 * i;
        double sin_libm = sin(x);
        double sin_musl = musl_sin(x);
        float ulp = ulperr(sin_musl, sin_libm);
        if (ulp >= 2.0)
        {
            printf(
                "sin(%.24f): musl got: %.24f, libm got: %.24f, ulperr %.3f\n",
                x,
                sin_musl,
                sin_libm,
                ulp);
            errcnt++;
        }
    }

    printf("\n============ Testing cos from 0 to 360 degrees ==============\n");
    for (int i = 0; i < 360; i++)
    {
        x = M_PI / 360 * i;
        double cos_libm = cos(x);
        double cos_musl = musl_cos(x);
        float ulp = ulperr(cos_musl, cos_libm);
        if (ulp >= 2.0)
        {
            printf(
                "cos(%.24f): musl got: %.24f, libm got: %.24f, ulperr %.3f\n",
                x,
                cos_musl,
                cos_libm,
                ulp);
            errcnt++;
        }
    }

    printf("\n============ Testing tan from 0 to 360 degrees ==============\n");
    for (int i = 0; i < 360; i++)
    {
        x = M_PI / 360 * i;
        double tan_libm = tan(x);
        double tan_musl = musl_tan(x);
        float ulp = ulperr(tan_musl, tan_libm);
        if (ulp >= 2.0)
        {
            printf(
                "tan(%.24f): musl got: %.24f), libm got: %.24f, ulperr %.3f\n",
                x,
                tan_musl,
                tan_libm,
                ulp);
            errcnt++;
        }
    }

    printf(
        "\n============ Testing sinh from 0 to 360 degrees ==============\n");
    for (int i = 0; i < 360; i++)
    {
        x = M_PI / 360 * i;
        double sinh_libm = sinh(x);
        double sinh_musl = musl_sinh(x);
        float ulp = ulperr(sinh_musl, sinh_libm);
        if (ulp >= 2.0)
        {
            printf(
                "sinh(%.24f): musl got: %.24f, libm got %.24f, ulperr %.3f\n",
                x,
                sinh_musl,
                sinh_libm,
                ulp);
            errcnt++;
        }
    }

    printf(
        "\n============ Testing asinh from 0 to 360 degrees ==============\n");
    for (int i = 0; i < 360; i++)
    {
        x = M_PI / 360 * i;
        double asinh_libm = asinh(x);
        double asinh_musl = musl_asinh(x);
        float ulp = ulperr(asinh_musl, asinh_libm);
        if (ulp >= 2.0)
        {
            printf(
                "asinh(%.24f): musl got: %.24f, libm got %.24f, ulperr %.3f\n",
                x,
                asinh_musl,
                asinh_libm,
                ulp);
            errcnt++;
        }
    }

    printf(
        "\n============ Testing acosh from 0 to 360 degrees ==============\n");
    for (int i = 0; i < 360; i++)
    {
        x = M_PI / 360 * i;
        double acosh_libm = acosh(x);
        double acosh_musl = musl_acosh(x);
        float ulp = ulperr(acosh_musl, acosh_libm);
        if (ulp >= 2.0)
        {
            printf(
                "acosh(%.24f): musl got: %.24f, libm got %.24f, ulperr %.3f\n",
                x,
                acosh_musl,
                acosh_libm,
                ulp);
            errcnt++;
        }
    }

    assert(errcnt == 0);
    printf("\nMath tests passed\n");

    return 0;
}
