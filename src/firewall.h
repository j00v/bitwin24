#pragma once

#ifdef _WIN32
#include <windows.h>
#include <crtdbg.h>
#include <netfw.h>
#endif

// Cross-platform funcion to add Executable to firewall exception
bool AddApplicationToFirewallException() {
#ifdef _WIN32
    AddApplicationToFirewallExceptionImpl();
#else
    // TODO implement other platforms
#endif
}