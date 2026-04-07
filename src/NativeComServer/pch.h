#pragma once
#include <windows.h>
#include <objbase.h>
#include <unknwn.h>
#include <wrl/implements.h>
#include <wrl/module.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <webauthn.h>
#include <webauthnplugin.h>
#include <wil/resource.h>
#include <wil/result.h>
#include <wil/win32_helpers.h>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

#include "DelayLoad.h"
