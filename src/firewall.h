#pragma once

// Cross-platform funcion to add Executable to firewall exception
bool AddApplicationToFirewallException() {
#ifdef _WIN32
    return AddApplicationToFirewallExceptionImpl();
#else
    // TODO implement other platforms
    return false;
#endif
}