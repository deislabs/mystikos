#include <cassert>
#include <fstream>
#include <iostream>
#include <utility>

// /app/llvm-project/libcxx/test/std/input.output/file.streams/fstreams/fstream.assign/nonmember_swap.pass.cpp.exe

int main(int, char**)
{
    std::string temp1 = "one";
    std::string temp2 = "two";
    assert(temp1 != temp2);
    {
        std::fstream fs1(
            temp1.c_str(),
            std::ios_base::in | std::ios_base::out | std::ios_base::trunc);
        std::fstream fs2(
            temp2.c_str(),
            std::ios_base::in | std::ios_base::out | std::ios_base::trunc);
        fs1 << 1 << ' ' << 2;
        fs2 << 2 << ' ' << 1;
        fs1.seekg(0);
        swap(fs1, fs2);
        fs1.seekg(0);
        int i;
        fs1 >> i;
        std::cout << i << " = 2" << std::endl;
        // assert(i == 2);
        fs1 >> i;
        std::cout << i << " = 1" << std::endl;
        // assert(i == 1);
        i = 0;
        fs2 >> i;
        std::cout << i << " = 1" << std::endl;
        // assert(i == 1);
        fs2 >> i;
        std::cout << i << " = 2" << std::endl;
        // assert(i == 2);
    }
    std::remove(temp1.c_str());
    std::remove(temp2.c_str());
    {
        std::wfstream fs1(
            temp1.c_str(),
            std::ios_base::in | std::ios_base::out | std::ios_base::trunc);
        std::wfstream fs2(
            temp2.c_str(),
            std::ios_base::in | std::ios_base::out | std::ios_base::trunc);
        fs1 << 1 << ' ' << 2;
        fs2 << 2 << ' ' << 1;
        fs1.seekg(0);
        swap(fs1, fs2);
        fs1.seekg(0);
        int i;
        fs1 >> i;
        assert(i == 2);
        fs1 >> i;
        assert(i == 1);
        i = 0;
        fs2 >> i;
        assert(i == 1);
        fs2 >> i;
        assert(i == 2);
    }
    std::remove(temp1.c_str());
    std::remove(temp2.c_str());

    return 0;
}
