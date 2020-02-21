#pragma once

// Cross-platform funcion to add Executable to firewall exception
#ifdef _WIN32
#include <windows.h>

bool AddApplicationToFirewallException(IN const wchar_t* fwProcessImageFileName, IN const wchar_t* fwName);
#else
// TODO implement other platforms
bool AddApplicationToFirewallException() {
    return false;
}
#endif