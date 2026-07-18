#include "PCH.h"

// Declare version independence rather than an explicit runtime allowlist.  SKSE
// checks an explicit list against its own notion of the runtime version, which
// is reported as 0 on GOG builds, so *every* listed version fails to match and
// the plugin is rejected before any of our code runs ("disabled, incompatible
// with current version of the game 0").  Address Library independence lets SKSE
// load us on any runtime; Hooks::IsVerifiedRuntime() is the real safety gate and
// fails closed on layouts we have not reverse-engineered.
//
// StructCompatibility must be Independent: CommonLibSSE NG carries both the pre-
// and post-1.6.629 struct layouts, and we support runtimes on both sides of that
// change (SE 1.5.97 and AE 1.6.x), so we can neither claim struct dependence nor
// flag post-629 structs exclusively.
SKSEPluginInfo(
    .Version = REL::Version{
        FFC_VERSION_MAJOR, FFC_VERSION_MINOR, FFC_VERSION_PATCH, 0 },
    .Name = "FasterFileCopy"sv,
    .Author = "FasterFileCopy contributors"sv,
    .StructCompatibility = SKSE::StructCompatibility::Independent,
    .RuntimeCompatibility = SKSE::VersionIndependence::AddressLibrary,
    .MinimumSKSEVersion = REL::Version{ 2, 0, 12, 0 }
)
