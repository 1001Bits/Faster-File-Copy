#include "CompressedReadPolicy.h"

#include <cstdint>
#include <iostream>

namespace
{
bool Require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << "FAILED: " << message << '\n';
    }
    return condition;
}
}

int main()
{
    bool ok = true;

    ok &= Require(!CompressedReadPolicy::SeekMoved(128, 128),
        "no-op current seek preserves active capture");
    ok &= Require(CompressedReadPolicy::SeekMoved(128, 129),
        "actual seek movement invalidates capture");

    auto progress = CompressedReadPolicy::ValidateNativeProgress(
        true, 0, 1024, 256, 256, true, true);
    ok &= Require(progress.valid && progress.cursorAfter == 256,
        "known sequential read advances cursor");

    progress = CompressedReadPolicy::ValidateNativeProgress(
        false, 0, 1024, 256, 256, true, true);
    ok &= Require(!progress.valid && progress.cursorAfter == 0,
        "unknown cursor never becomes an assumed byte-zero read");

    progress = CompressedReadPolicy::ValidateNativeProgress(
        true, 0, 0, 256, 256, true, true);
    ok &= Require(progress.valid && progress.cursorAfter == 256,
        "unknown size can advance a lifecycle-known cursor");
    ok &= Require(!CompressedReadPolicy::ValidateNativeProgress(
        true, 900, 1024, 256, 256, true, true).valid,
        "read beyond known decompressed size is rejected");
    ok &= Require(!CompressedReadPolicy::ValidateNativeProgress(
        true, 0, 1024, 128, 256, true, true).valid,
        "native read larger than requested is rejected");

    if (ok) {
        std::cout << "Compressed read policy tests passed\n";
    }
    return ok ? 0 : 1;
}
