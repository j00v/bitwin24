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


HRESULT WindowsFirewallInitialize(OUT INetFwProfile** fwProfile)
{
    _ASSERT(fwProfile != NULL);
    *fwProfile = NULL;

    INetFwMgr* fwMgr = NULL;
    // Create an instance of the firewall settings manager.
    HRESULT hr = CoCreateInstance(
        __uuidof(NetFwMgr),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwMgr),
        (void**)&fwMgr
    );
    if (FAILED(hr))
    {
        printf("CoCreateInstance failed: 0x%08lx\n", hr);
        goto error;
    }

    INetFwPolicy* fwPolicy = NULL;
    // Retrieve the local firewall policy.
    hr = fwMgr->get_LocalPolicy(&fwPolicy);
    if (FAILED(hr))
    {
        printf("get_LocalPolicy failed: 0x%08lx\n", hr);
        goto error;
    }

    // Retrieve the firewall profile currently in effect.
    hr = fwPolicy->get_CurrentProfile(fwProfile);
    if (FAILED(hr))
    {
        printf("get_CurrentProfile failed: 0x%08lx\n", hr);
        goto error;
    }

error:

    // Release the local firewall policy.
    if (fwPolicy != NULL)
    {
        fwPolicy->Release();
    }

    // Release the firewall settings manager.
    if (fwMgr != NULL)
    {
        fwMgr->Release();
    }

    return hr;
}


HRESULT WindowsFirewallIsOn(IN INetFwProfile* fwProfile, OUT BOOL* fwOn)
{
    _ASSERT(fwProfile != NULL);
    _ASSERT(fwOn != NULL);
    *fwOn = FALSE;


    VARIANT_BOOL fwEnabled;
    // Get the current state of the firewall.
    HRESULT hr = fwProfile->get_FirewallEnabled(&fwEnabled);
    if (FAILED(hr))
    {
        printf("get_FirewallEnabled failed: 0x%08lx\n", hr);
        return hr;
    }

    // Check to see if the firewall is on.
    if (fwEnabled != VARIANT_FALSE)
    {
        *fwOn = TRUE;
        printf("The firewall is on.\n");
    }
    else
    {
        printf("The firewall is off.\n");
    }

    return hr;
}



HRESULT WindowsFirewallAppIsEnabled(
            IN INetFwProfile* fwProfile,
            IN const wchar_t* fwProcessImageFileName,
            OUT BOOL* fwAppEnabled
        )
{
    HRESULT hr = S_OK;
    VARIANT_BOOL fwEnabled;

    _ASSERT(fwProfile != NULL);
    _ASSERT(fwProcessImageFileName != NULL);
    _ASSERT(fwAppEnabled != NULL);

    *fwAppEnabled = FALSE;

    // Retrieve the authorized application collection.
    INetFwAuthorizedApplications* fwApps = NULL;
    hr = fwProfile->get_AuthorizedApplications(&fwApps);
    if (FAILED(hr))
    {
        printf("get_AuthorizedApplications failed: 0x%08lx\n", hr);
        goto error;
    }

    // Allocate a BSTR for the process image file name.
    BSTR fwBstrProcessImageFileName = SysAllocString(fwProcessImageFileName);
    if (fwBstrProcessImageFileName == NULL)
    {
        hr = E_OUTOFMEMORY;
        printf("SysAllocString failed: 0x%08lx\n", hr);
        goto error;
    }

    // Attempt to retrieve the authorized application.
    INetFwAuthorizedApplication* fwApp = NULL;
    hr = fwApps->Item(fwBstrProcessImageFileName, &fwApp);
    if (SUCCEEDED(hr))
    {
        // Find out if the authorized application is enabled.
        hr = fwApp->get_Enabled(&fwEnabled);
        if (FAILED(hr))
        {
            printf("get_Enabled failed: 0x%08lx\n", hr);
            goto error;
        }

        if (fwEnabled != VARIANT_FALSE)
        {
            // The authorized application is enabled.
            *fwAppEnabled = TRUE;

            printf(
                "Authorized application %lS is enabled in the firewall.\n",
                fwProcessImageFileName
                );
        }
        else
        {
            printf(
                "Authorized application %lS is disabled in the firewall.\n",
                fwProcessImageFileName
                );
        }
    }
    else
    {
        // The authorized application was not in the collection.
        hr = S_OK;

        printf(
            "Authorized application %lS is disabled in the firewall.\n",
            fwProcessImageFileName
            );
    }

error:

    // Free the BSTR.
    SysFreeString(fwBstrProcessImageFileName);

    // Release the authorized application instance.
    if (fwApp != NULL)
    {
        fwApp->Release();
    }

    // Release the authorized application collection.
    if (fwApps != NULL)
    {
        fwApps->Release();
    }

    return hr;
}


HRESULT WindowsFirewallAddApp(
    IN INetFwProfile* fwProfile,
    IN const wchar_t* fwProcessImageFileName,
    IN const wchar_t* fwName
)
{
    _ASSERT(fwProfile != NULL);
    _ASSERT(fwProcessImageFileName != NULL);
    _ASSERT(fwName != NULL);

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
        goto error;
    }

    // Only add the application if it isn't already authorized.
    if (fwAppEnabled)
    {
        goto error;
    }

    // Retrieve the authorized application collection.
    INetFwAuthorizedApplications* fwApps = NULL;
    hr = fwProfile->get_AuthorizedApplications(&fwApps);
    if (FAILED(hr))
    {
        printf("get_AuthorizedApplications failed: 0x%08lx\n", hr);
        goto error;
    }

    // Create an instance of an authorized application.
    INetFwAuthorizedApplication* fwApp = NULL;
    hr = CoCreateInstance(
        __uuidof(NetFwAuthorizedApplication),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwAuthorizedApplication),
        (void**)&fwApp
    );
    if (FAILED(hr))
    {
        printf("CoCreateInstance failed: 0x%08lx\n", hr);
        goto error;
    }

    // Allocate a BSTR for the process image file name.
    BSTR fwBstrProcessImageFileName = SysAllocString(fwProcessImageFileName);
    if (fwBstrProcessImageFileName == NULL)
    {
        hr = E_OUTOFMEMORY;
        printf("SysAllocString failed: 0x%08lx\n", hr);
        goto error;
    }

    // Set the process image file name.
    hr = fwApp->put_ProcessImageFileName(fwBstrProcessImageFileName);
    if (FAILED(hr))
    {
        printf("put_ProcessImageFileName failed: 0x%08lx\n", hr);
        goto error;
    }

    // Allocate a BSTR for the application friendly name.
    BSTR fwBstrName = SysAllocString(fwName);
    if (SysStringLen(fwBstrName) == 0)
    {
        hr = E_OUTOFMEMORY;
        printf("SysAllocString failed: 0x%08lx\n", hr);
        goto error;
    }

    // Set the application friendly name.
    hr = fwApp->put_Name(fwBstrName);
    if (FAILED(hr))
    {
        printf("put_Name failed: 0x%08lx\n", hr);
        goto error;
    }

    // Add the application to the collection.
    hr = fwApps->Add(fwApp);
    if (FAILED(hr))
    {
        printf("Add failed: 0x%08lx\n", hr);
        goto error;
    }

    printf("Authorized application %lS is now enabled in the firewall.\n", fwProcessImageFileName);

error:

    // Free the BSTRs.
    SysFreeString(fwBstrName);
    SysFreeString(fwBstrProcessImageFileName);

    // Release the authorized application instance.
    if (fwApp != NULL)
    {
        fwApp->Release();
    }

    // Release the authorized application collection.
    if (fwApps != NULL)
    {
        fwApps->Release();
    }

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
        if (SUCCEEDED(comInit))
        {
            CoUninitialize();
        }
    }

    HRESULT hr = E_FAIL;
};

struct INetFwProfileResource
{
    INetFwProfileResource() {
        // Retrieve the firewall profile currently in effect.
        HRESULT hr = WindowsFirewallInitialize(&fwProfile);
        if (FAILED(hr))
        {
            throw std::runtime_error{ std::string{"WindowsFirewallInitialize failed: "} + std::to_string(hr) };
        }
    }

    ~INetFwProfileResource() {
        // Release the firewall profile.
        if (fwProfile != NULL)
        {
            fwProfile->Release();
        }
    }

    INetFwProfile* profile = NULL;
};

bool AddApplicationToFirewallExceptionImpl()
{
    // Initialize COM.
    try {
        COMResource com;

        // Add Windows Messenger to the authorized application collection.
        INetFwProfileResource fwProfile;
        hr = WindowsFirewallAddApp(fwProfile->profile, L"%ProgramFiles%\\Messenger\\msmsgs.exe", L"Windows Messenger");
        
        return FAILED(hr);
    }
    catch(...) {
        return false;
    }
}
#endif