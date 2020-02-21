/*
    Copyright (c) Microsoft Corporation
    SYNOPSIS
        Sample code for the Windows Firewall COM interface.
        https://docs.microsoft.com/en-us/previous-versions//aa364726(v=vs.85)
*/

#include "firewall.h"

#if _WIN32

#include <windows.h>
#include <crtdbg.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#include <stdio.h>

#include <stdexcept>
#include <string>

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )


struct INetFwMgrResource {
    INetFwMgrResource() {
        // Create an instance of the firewall settings manager.
        HRESULT hr = CoCreateInstance(
            __uuidof(NetFwMgr),
            nullptr,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwMgr),
            (void**)&fwMgr
        );

        if (FAILED(hr))
        {
            throw std::runtime_error{ std::string{"CoCreateInstance failed: "} + std::to_string(hr) };
        }
    }

    ~INetFwMgrResource() {
        // Release the firewall settings manager.
        if (fwMgr != nullptr)
        {
            fwMgr->Release();
        }
    }

    INetFwMgr* operator->() {
        return fwMgr;
    }

    INetFwMgr* fwMgr = nullptr;
};


struct INetFwPolicyResource {
    INetFwPolicyResource(INetFwMgr& fwMgr) {
        // Retrieve the local firewall policy.
        HRESULT hr = fwMgr.get_LocalPolicy(&fwPolicy);
        if (FAILED(hr))
        {
            throw std::runtime_error{ std::string{"get_LocalPolicy failed: "} + std::to_string(hr) };
        }
    }

    ~INetFwPolicyResource() {
        // Release the local firewall policy.
        if (fwPolicy != nullptr)
        {
            fwPolicy->Release();
        }
    }

    INetFwPolicy* operator->() {
        return fwPolicy;
    }

    INetFwPolicy* fwPolicy = nullptr;
};


HRESULT WindowsFirewallInitialize(OUT INetFwProfile** fwProfile)
{
    _ASSERT(fwProfile != nullptr);
    *fwProfile = nullptr;

    INetFwMgrResource fwMgr;
    INetFwPolicyResource fwPolicy{ *fwMgr.fwMgr };

    // Retrieve the firewall profile currently in effect.
    return fwPolicy->get_CurrentProfile(fwProfile);
}

struct INetFwAuthorizedApplicationsResource {
    INetFwAuthorizedApplicationsResource(INetFwProfile& fwProfile) {
        // Retrieve the authorized application collection.
        HRESULT hr = fwProfile.get_AuthorizedApplications(&fwApps);
        if (FAILED(hr))
        {
            throw std::runtime_error{ std::string{"get_AuthorizedApplications failed: "} + std::to_string(hr) };
        }

    }

    ~INetFwAuthorizedApplicationsResource() {
        // Release the authorized application collection.
        if (fwApps != nullptr)
        {
            fwApps->Release();
        }
    }

    INetFwAuthorizedApplications* operator->() {
        return fwApps;
    }

    INetFwAuthorizedApplications* fwApps = nullptr;
};

struct INetFwAuthorizedApplicationResource {
    INetFwAuthorizedApplicationResource(const wchar_t* fwProcessImageFileName, const wchar_t* fwName) {
        // Create an instance of an authorized application.
        HRESULT hr = CoCreateInstance(
            __uuidof(NetFwAuthorizedApplication),
            nullptr,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwAuthorizedApplication),
            (void**)&fwApp
        );
        if (FAILED(hr))
        {
            throw std::runtime_error{ std::string{"CoCreateInstance failed: "} + std::to_string(hr) };
        }

        // Allocate a BSTR for the process image file name.
        BSTR fwBstrProcessImageFileName = SysAllocString(fwProcessImageFileName);
        if (fwBstrProcessImageFileName == nullptr)
        {
            throw std::runtime_error{ std::string{"SysAllocString failed: "} + std::to_string(hr) };
        }

        // Set the process image file name.
        hr = fwApp->put_ProcessImageFileName(fwBstrProcessImageFileName);
        if (FAILED(hr))
        {
            throw std::runtime_error{ std::string{"put_ProcessImageFileName failed: "} + std::to_string(hr) };
        }

        // Allocate a BSTR for the application friendly name.
        BSTR fwBstrName = SysAllocString(fwName);
        if (SysStringLen(fwBstrName) == 0)
        {
            throw std::runtime_error{ std::string{"SysAllocString failed: "} + std::to_string(hr) };
        }

        // Set the application friendly name.
        hr = fwApp->put_Name(fwBstrName);
        if (FAILED(hr))
        {
            throw std::runtime_error{ std::string{"put_Name failed: "} + std::to_string(hr) };
        }

        // Free the BSTRs.
        SysFreeString(fwBstrName);
        SysFreeString(fwBstrProcessImageFileName);
    }

    ~INetFwAuthorizedApplicationResource() {
        // Release the authorized application instance.
        if (fwApp != nullptr)
        {
            fwApp->Release();
        }
    }

    INetFwAuthorizedApplication* operator->() {
        return fwApp;
    }

    INetFwAuthorizedApplication* fwApp = nullptr;
};

HRESULT WindowsFirewallAppIsEnabled(
            IN INetFwProfile* fwProfile,
            IN const wchar_t* fwProcessImageFileName,
            OUT BOOL* fwAppEnabled
        )
{
    HRESULT hr = S_OK;

    _ASSERT(fwProfile != nullptr);
    _ASSERT(fwProcessImageFileName != nullptr);
    _ASSERT(fwAppEnabled != nullptr);

    *fwAppEnabled = FALSE;

    // Allocate a BSTR for the process image file name.
    BSTR fwBstrProcessImageFileName = SysAllocString(fwProcessImageFileName);
    if (fwBstrProcessImageFileName == nullptr)
    {
        printf("SysAllocString failed: 0x%08lx\n", hr);
        return E_OUTOFMEMORY;
    }

    // Retrieve the authorized application collection.
    INetFwAuthorizedApplicationsResource fwApps{ *fwProfile };
    // Attempt to retrieve the authorized application.
    INetFwAuthorizedApplication* fwApp = nullptr;
    hr = fwApps->Item(fwBstrProcessImageFileName, &fwApp);
    if (SUCCEEDED(hr))
    {
        VARIANT_BOOL fwEnabled;
        // Find out if the authorized application is enabled.
        hr = fwApp->get_Enabled(&fwEnabled);
        if (FAILED(hr))
        {
            printf("get_Enabled failed: 0x%08lx\n", hr);
            return hr;
        }

        if (fwEnabled != VARIANT_FALSE)
        {
            // The authorized application is enabled.
            *fwAppEnabled = TRUE;

            printf("Authorized application %lS is enabled in the firewall.\n", fwProcessImageFileName);
        }
        else
        {
            printf("Authorized application %lS is disabled in the firewall.\n", fwProcessImageFileName);
        }
    }
    else
    {
        // The authorized application was not in the collection.
        hr = S_OK;

        printf("Authorized application %lS is disabled in the firewall.\n",fwProcessImageFileName);
    }

    // Free the BSTR.
    SysFreeString(fwBstrProcessImageFileName);

    return hr;
}

HRESULT WindowsFirewallAddApp(
    IN INetFwProfile* fwProfile,
    IN const wchar_t* fwProcessImageFileName,
    IN const wchar_t* fwName
)
{
    _ASSERT(fwProfile != nullptr);
    _ASSERT(fwProcessImageFileName != nullptr);
    _ASSERT(fwName != nullptr);

    // First check to see if the application is already authorized.
    BOOL fwAppEnabled;
    HRESULT hr = WindowsFirewallAppIsEnabled(
        fwProfile,
        fwProcessImageFileName,
        &fwAppEnabled
    );
    if (FAILED(hr))
    {
        printf("WindowsFirewallAppIsEnabled failed: 0x%08lx\n", hr);
        return hr;
    }

    // Only add the application if it isn't already authorized.
    if (fwAppEnabled)
    {
        return S_OK;
    }

    // Add the application to the collection.
    INetFwAuthorizedApplicationResource fwApp{fwProcessImageFileName, fwName};
    INetFwAuthorizedApplicationsResource fwApps{*fwProfile};
    hr = fwApps->Add(fwApp.fwApp);
    if (FAILED(hr))
    {
        printf("Add failed: 0x%08lx\n", hr);
    }

    printf("Authorized application %lS is now enabled in the firewall.\n", fwProcessImageFileName);

    return hr;
}

struct COMResource {
    COMResource() {
        hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
        // initialized with a different mode. Since we don't care what the mode is,
        // we'll just use the existing mode.
        if (hr != RPC_E_CHANGED_MODE && FAILED(hr))
        {
            throw std::runtime_error{ std::string{"CoInitializeEx failed: "} + std::to_string(hr) };
        }
    }

    ~COMResource() {
        // Uninitialize COM.
        if (SUCCEEDED(hr))
        {
            CoUninitialize();
        }
    }

    HRESULT hr = E_FAIL;
};

struct INetFwProfileResource {
    INetFwProfileResource() {
        // Retrieve the firewall profile currently in effect.
        HRESULT hr = WindowsFirewallInitialize(&profile);
        if (FAILED(hr))
        {
            throw std::runtime_error{ std::string{"WindowsFirewallInitialize failed: "} + std::to_string(hr) };
        }
    }

    ~INetFwProfileResource() {
        // Release the firewall profile.
        if (profile != nullptr)
        {
            profile->Release();
        }
    }

    INetFwProfile* profile = nullptr;
};

bool AddApplicationToFirewallException(IN const wchar_t* fwProcessImageFileName, IN const wchar_t* fwName)
{
    // Initialize COM.
    try {
        COMResource com;

        // Add Windows Messenger to the authorized application collection.
        INetFwProfileResource fwProfile;
        HRESULT hr = WindowsFirewallAddApp(fwProfile.profile, fwProcessImageFileName, fwName);
        
        return FAILED(hr);
    }
    catch(...) {
        return false;
    }
}
#endif