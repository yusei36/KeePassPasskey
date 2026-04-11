# NativeComServer (C++ — not part of the current build)

This directory contains the original C++ implementation of the COM server / passkey provider.
It has been superseded by the C# project at `src/PasskeyPluginProxy/` and is no longer included in the solution build.

## Prerequisites (if building manually)

- Visual Studio 2026+ (toolset `v145`)
- Windows SDK 10.0.26100.0+

To build with an older toolset, override at the command line:

```
msbuild NativeComServer.vcxproj /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143
```
