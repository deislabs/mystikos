struct __processor_model
{
    unsigned int __cpu_vendor;
    unsigned int __cpu_type;
    unsigned int __cpu_subtype;
    unsigned int __cpu_features[1];
};

__attribute__((weak))
struct __processor_model __cpu_model;

__attribute__((weak))
__attribute__ ((constructor(101)))
int __cpu_indicator_init (void)
{
    return 0;
}
