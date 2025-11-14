#include "primitive_sa.h" // do not change this

setup_params start()
{
    return setup();
}

alloc_result begin(setup_params params)
{
    alloc_result result;
    for (int i = 0; i < 10; i ++) {
        alloc_result temp = alloc(params);
        result.r0 += (uint64_t)temp.r0;
        result.r1 += (uint64_t)temp.r1;
    }
    return result;
}

void end()
{
    // keep it empty.
}

int main()
{
    setup_params params = start();
    alloc_result final_result = begin(params);
    end();
    return 0;
}
