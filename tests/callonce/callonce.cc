#include <mutex>

int main() {
    static std::once_flag f;
    std::call_once(f, []{});
    printf("call_once() passed\n");
}
