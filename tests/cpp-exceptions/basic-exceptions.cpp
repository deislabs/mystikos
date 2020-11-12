#include <iostream>
#include <cassert>
#include <string>

using namespace std;

bool check_out_of_range_exception()
{
    bool caught = false;
    string s = "xyz";
    try
    {
        // access out of bounds index
        cout << s.at(3) << endl;
    }
    catch (const std::out_of_range& oor)
    {
        caught = true;
    }
    
    return caught;
}

struct myexception : std::exception
{
};

bool check_custom_exception()
{
    bool caught = false;
    try
    {
        throw myexception();
    }
    catch (myexception& e)
    {
        caught = true;
    }

    return caught;
}

void y3()
{
    throw myexception();
}

void y2()
{
    y3();
}

void y1()
{
    y2();
}

bool check_nested_exception()
{
    bool caught = false;

    try
    {
        y1();
    }
    catch (myexception& e)
    {
        try
        {
            throw e;
        }
        catch (myexception& e)
        {
            caught = true;
        }
    }

    return caught;
}

int main(int argc, const char* argv[])
{

    assert(check_out_of_range_exception());
    assert(check_custom_exception());
    assert(check_nested_exception());

    cout << "=== passed tests (" << argv[0] << ")" << endl;

    return 0;
}
