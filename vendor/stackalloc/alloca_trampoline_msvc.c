#include <stddef.h>
#ifdef _MSC_VER
#include <malloc.h>
#endif

void _alloca_trampoline(size_t num, void (*callback)(void* ptr, void* data), void* data)
{
    void* ptr = _alloca(num);
    callback(ptr, data);
}
