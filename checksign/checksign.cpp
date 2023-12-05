// checksign.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>


#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")

#pragma comment(lib, "wintrust.lib")

LPSTR GetCertificateDescription(PCCERT_CONTEXT pCertCtx)
{
    DWORD dwStrType;
    DWORD dwCount;
    LPSTR szSubjectRDN = NULL;

    dwStrType = CERT_X500_NAME_STR;
    dwCount = CertGetNameString(pCertCtx,
        CERT_NAME_RDN_TYPE,
        0,
        &dwStrType,
        NULL,
        0);
    if (dwCount)
    {
        szSubjectRDN = (LPSTR)LocalAlloc(0, dwCount * sizeof(TCHAR));
        CertGetNameString(pCertCtx,
            CERT_NAME_RDN_TYPE,
            0,
            &dwStrType,
            szSubjectRDN,
            dwCount);
    }

    return szSubjectRDN;
}

bool VerifyModuleSignature(const char* pwszSourceFile) {
    LONG lStatus;
    DWORD dwLastError;

    bool ret = false;
    // Initialize the WINTRUST_FILE_INFO structure.

    int num = MultiByteToWideChar(0, 0, pwszSourceFile, -1, NULL, 0);
    wchar_t* wide = new wchar_t[num];
    MultiByteToWideChar(0, 0, pwszSourceFile, -1, wide, num);

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = wide;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

    1) The certificate used to sign the file chains up to a root
    certificate located in the trusted root certificate store. This
    implies that the identity of the publisher has been verified by
    a certification authority.

    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the
    end entity certificate is stored in the trusted publisher store,
    implying that the user trusts content from this publisher.

    3) The end entity certificate has sufficient permission to sign
    code, as indicated by the presence of a code signing EKU or no
    EKU.
    */

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    // Initialize the WinVerifyTrust input data structure.

    // Default all fields to 0.
    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);

    // Use default code signing EKU.
    WinTrustData.pPolicyCallbackData = NULL;

    // No data to pass to SIP.
    WinTrustData.pSIPClientData = NULL;

    // Disable WVT UI.
    WinTrustData.dwUIChoice = WTD_UI_NONE;

    // No revocation checking.
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

    // Verify an embedded signature on a file.
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

    // Verify action.
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    // Verification sets this value.
    WinTrustData.hWVTStateData = NULL;

    // Not used.
    WinTrustData.pwszURLReference = NULL;

    // This is not applicable if there is no UI because it changes 
    // the UI to accommodate running applications instead of 
    // installing applications.
    WinTrustData.dwUIContext = 0;

    // Set pFile.
    WinTrustData.pFile = &FileData;

    // WinVerifyTrust verifies signatures as specified by the GUID 
    // and Wintrust_Data.
    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    switch (lStatus)
    {
    case ERROR_SUCCESS:
        /*
        Signed file:
            - Hash that represents the subject is trusted.

            - Trusted publisher without any verification errors.

            - UI was disabled in dwUIChoice. No publisher or
                time stamp chain errors.

            - UI was enabled in dwUIChoice and the user clicked
                "Yes" when asked to install and run the signed
                subject.
        */
        printf("The file \"%s\" is signed and the signature was verified.\n", pwszSourceFile);
        ret = true;
        break;

    case TRUST_E_NOSIGNATURE:
        // The file was not signed or had a signature 
        // that was not valid.

        // Get the reason for no signature.
        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError)
        {
            // The file was not signed.
            printf("The file \"%s\" is not signed.\n",
                pwszSourceFile);
        }
        else
        {
            // The signature was not valid or there was an error 
            // opening the file.
            printf("An unknown error occurred trying to  verify the signature of the \"%s\" file.\n",
                pwszSourceFile);
        }

        break;

    case TRUST_E_EXPLICIT_DISTRUST:
        // The hash that represents the subject or the publisher 
        // is not allowed by the admin or user.
        printf("The signature is present, but specifically  disallowed.\n");
        break;

    case TRUST_E_SUBJECT_NOT_TRUSTED:
        // The user clicked "No" when asked to install and run.
        printf("The signature is present, but not  trusted.\n");
        break;

    case CRYPT_E_SECURITY_SETTINGS:
        /*
        The hash that represents the subject or the publisher
        was not explicitly trusted by the admin and the
        admin policy has disabled user trust. No signature,
        publisher or time stamp errors.
        */
        printf("CRYPT_E_SECURITY_SETTINGS - The hash  representing the subject or the publisher wasn't explicitly trusted by the admin and admin policy has disabled user trust. No signature, publisher or timestamp errors.\n");
        break;

    default:
        // The UI was disabled in dwUIChoice or the admin policy 
        // has disabled user trust. lStatus contains the 
        // publisher or time stamp chain error.
        printf("Error is: 0x%x.\n",
            lStatus);
        break;
    }



    if (ret)
    {
        // 获取签名信息

        // retreive the signer certificate and display its information
        CRYPT_PROVIDER_DATA const* psProvData = NULL;
        CRYPT_PROVIDER_SGNR* psProvSigner = NULL;
        CRYPT_PROVIDER_CERT* psProvCert = NULL;
        FILETIME                   localFt;
        SYSTEMTIME                 sysTime;

        psProvData = WTHelperProvDataFromStateData(WinTrustData.hWVTStateData);
        if (psProvData)
        {
            psProvSigner = WTHelperGetProvSignerFromChain((PCRYPT_PROVIDER_DATA)psProvData, 0, FALSE, 0);
            if (psProvSigner)
            {
                FileTimeToLocalFileTime(&psProvSigner->sftVerifyAsOf, &localFt);
                FileTimeToSystemTime(&localFt, &sysTime);

                printf("Signature Date = %.2d/%.2d/%.4d at %.2d:%2.d:%.2d\n", sysTime.wDay, sysTime.wMonth, sysTime.wYear, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);

                psProvCert = WTHelperGetProvCertFromChain(psProvSigner, 0);
                if (psProvCert)
                {
                    LPTSTR szCertDesc = GetCertificateDescription(psProvCert->pCert);
                    if (szCertDesc)
                    {
                        printf("File Signer = %s\n", szCertDesc);
                        LocalFree(szCertDesc);
                    }
                }

                if (psProvSigner->csCounterSigners)
                {
                    printf("\n");
                    // Timestamp information
                    FileTimeToLocalFileTime(&psProvSigner->pasCounterSigners[0].sftVerifyAsOf, &localFt);
                    FileTimeToSystemTime(&localFt, &sysTime);

                    // _tprintf(_T("Timestamp Date = %.2d/%.2d/%.4d at %.2d:%2.d:%.2d\n"), sysTime.wDay, sysTime.wMonth, sysTime.wYear, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
                    psProvCert = WTHelperGetProvCertFromChain(&psProvSigner->pasCounterSigners[0], 0);
                    if (psProvCert)
                    {
                        LPTSTR szCertDesc = GetCertificateDescription(psProvCert->pCert);
                        if (szCertDesc)
                        {
                            printf("Timestamp Signer = %s\n", szCertDesc);
                            LocalFree(szCertDesc);
                        }
                    }
                }
            }
        }






    }


    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);


    delete wide;
    return ret;

}

int main(int argc, char* argv[])
{
    if (argc > 1)
    {
        VerifyModuleSignature(argv[1]);
    }
    else 
    {
        VerifyModuleSignature(argv[0]);
    }

   
    return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
