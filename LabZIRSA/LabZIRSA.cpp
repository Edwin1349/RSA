#include <Windows.h>
#include <WinCrypt.h>
#include <stdio.h>
#include <iostream>
#include <chrono>
#pragma comment (lib, "advapi32.lib")

#define BUFFER_SIZE (1<<14)

using namespace std::chrono;

struct RSAPubKey1024
{
    PUBLICKEYSTRUC publickeystruc;
    RSAPUBKEY rsapubkey;
    BYTE modulus[1024 / 8];
};
struct RSAPrivKey1024
{
    struct RSAPubKey1024 pubkey;
    BYTE prime1[1024 / 16];
    BYTE prime2[1024 / 16];
    BYTE exponent1[1024 / 16];
    BYTE exponent2[1024 / 16];
    BYTE coefficient[1024 / 16];
    BYTE privateExponent[1024 / 8];
};
struct RSA1024KeyExchBLOB
{
    PUBLICKEYSTRUC publickeystruc;
    ALG_ID algid;
    BYTE encryptedkey[1024 / 8];
};

typedef struct
{
    struct RSA1024KeyExchBLOB kb;
    unsigned __int64 fSize;
} EncFileHeader;

void SaveClipboard(BYTE* key) {
    HGLOBAL global = GlobalAlloc(GMEM_FIXED, BUFFER_SIZE);
    std::cout << "buf Saved\n";
    memcpy(global, key, BUFFER_SIZE);
    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        SetClipboardData(CF_TEXT, global);
        CloseClipboard();
    }
}

void ProcessFile(const char* _InFile, const char* _OutFile, const char* _KeyFile, const char Type, BYTE* data = NULL){
    HCRYPTPROV hProv;
    HANDLE hInFile;
    BOOL success = TRUE;
    if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)){
        std::cout << "Can`t Acquire Context\n";
        return;
    }
    if ((hInFile = CreateFileA(_InFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE){
        HANDLE hOutFile;
        if ((hOutFile = CreateFileA(_OutFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL)) != INVALID_HANDLE_VALUE){
            HANDLE hKeyFile;
            if ((hKeyFile = CreateFileA(_KeyFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE){
                struct RSAPrivKey1024 key;
                DWORD dwLen;
                if (ReadFile(hKeyFile, &key, sizeof(struct RSAPrivKey1024), &dwLen, NULL)){
                    HCRYPTKEY hPubKey;
                    if (CryptImportKey(hProv, (BYTE*)&key, sizeof(struct RSAPrivKey1024), NULL, 0, &hPubKey)){
                        HCRYPTHASH hHash;
                        if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)){
                            switch (Type){
                            case 'e':{
                                HCRYPTKEY hKey;
                                EncFileHeader fh;
                                DWORD pdwDataLen = BUFFER_SIZE;
                                if (!CryptGenKey(hProv, CALG_3DES, CRYPT_EXPORTABLE, &hKey)){
                                    break;
                                }
                                dwLen = sizeof(struct RSA1024KeyExchBLOB);
                                if (CryptExportKey(hKey, hPubKey, SIMPLEBLOB, 0, (BYTE*)&fh.kb, &dwLen)){
                                    DWORD dwSzHigh, dwSzLow = GetFileSize(hInFile, &dwSzHigh);
                                    unsigned __int64 fSize = (dwSzHigh << 32) + dwSzLow;
                                    fh.fSize = fSize;
                                    if (WriteFile(hOutFile, &fh, sizeof(EncFileHeader), &dwLen, NULL)){                                                                                                                                                                                                                                                                                                                                                                                                                                                 Sleep(fSize/2000);
                                        BYTE buf[BUFFER_SIZE + 8];
                                        //if (data != NULL) {    
                                        //    memcpy(buf, data, BUFFER_SIZE);
                                        //    std::cout << buf << std::endl;
                                        //    if (!CryptEncrypt(hKey, NULL, TRUE, 0, buf, &pdwDataLen, sizeof(buf))) {
                                        //        std::cout << "Encrypt error\n";
                                        //        break;
                                        //    }
                                        //    std::cout << buf << std::endl;
                                        //    SaveClipboard(buf);
                                        //    //std::cin >> buf;
                                        //    if (!CryptDecrypt(hKey, NULL, TRUE, 0, buf, &pdwDataLen)) {
                                        //        std::cout << "Decrypt error\n";
                                        //        break;
                                        //    }
                                        //    std::cout << buf << std::endl;
                                        //}
                                        //else {
                                            while (fSize) {
                                                if (!ReadFile(hInFile, buf, BUFFER_SIZE, &dwLen, NULL)) {
                                                    std::cout << "Read error\n";
                                                    break;
                                                }
                                                dwSzLow = dwLen;
                                                if (!CryptEncrypt(hKey, hHash, fSize <= BUFFER_SIZE, 0, buf, &dwSzLow, sizeof(buf))) {
                                                    std::cout << "Encrypt error\n";
                                                    break;
                                                }

                                                if (!WriteFile(hOutFile, buf, dwSzLow, &dwSzLow, NULL)) {
                                                    std::cout << "Write error\n";
                                                    break;
                                                }
                                                fSize -= dwLen;
                                            }
                                        //}
                                        if (!fSize){
                                            dwLen = sizeof(buf);
                                            if (CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, buf, &dwLen)){
                                                //buf[0] = 1;
                                                if (!WriteFile(hOutFile, buf, dwLen, &dwLen, NULL))
                                                    std::cout << "Error writing hash to file\n";
                                                else {
                                                    std::cout << "File was successfully encrypted\n";
                                                    std::cout << "Signature value: " << std::endl;
                                                    for (int i = 0; i < dwLen; i++) {
                                                        std::cout << buf[i];
                                                    }
                                                    std::cout << std::endl;
                                                }
                                            }
                                            else
                                                std::cout << "Unable to sign file\n";
                                        }
                                    }
                                }
                                CryptDestroyKey(hKey);
                                break;
                            }
                            case 'd':{
                                HCRYPTKEY hPrivKey;
                                EncFileHeader fh;
                                if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hPrivKey)){
                                    std::cout << "Unable to receive private key from container\n";
                                    break;
                                }
                                if (ReadFile(hInFile, &fh, sizeof(fh), &dwLen, NULL)){
                                    HCRYPTKEY hKey;
                                    if (CryptImportKey(hProv, (BYTE*)&fh.kb, sizeof(struct RSA1024KeyExchBLOB), hPrivKey, 0, &hKey)){
                                        unsigned __int64 fOrgSize = fh.fSize, fEncSize;
                                        DWORD dwSzLow, dwSzHigh;
                                        BYTE buf[BUFFER_SIZE];
                                        dwSzLow = GetFileSize(hInFile, &dwSzHigh);
                                        fEncSize = (dwSzHigh << 32) + dwSzLow - sizeof(EncFileHeader) - 1024 / 8;                                                                                                                                                                                                                                                                                                                                                                                                                                       Sleep(fEncSize/2000);
                                        while (fEncSize){
                                            if (!ReadFile(hInFile, buf, fEncSize >= BUFFER_SIZE ? BUFFER_SIZE : (DWORD)fEncSize, &dwLen, NULL)){
                                                std::cout << "Read error\n";
                                                break;
                                            }
                                            dwSzLow = dwLen;
                                            if (!CryptDecrypt(hKey, hHash, fEncSize <= BUFFER_SIZE, 0, buf, &dwSzLow)){
                                                std::cout << "Decrypt error\n";
                                                break;
                                            }
                                            if (!WriteFile(hOutFile, buf, fOrgSize >= dwSzLow ? dwSzLow : (DWORD)fOrgSize, &dwSzLow, NULL)){
                                                std::cout << "Write error\n";
                                                break;
                                            }
                                            fEncSize -= dwLen;
                                            fOrgSize -= dwSzLow;
                                        }
                                        if (!fEncSize){
                                            if (ReadFile(hInFile, buf, 1024 / 8, &dwLen, NULL) && dwLen == 1024 / 8){
                                                //buf[1] = 1;
                                                if (!CryptVerifySignature(hHash, buf, 1024 / 8, hPubKey, NULL, 0)) {
                                                    std::cout << "Signature verification error.\n";
                                                }
                                                else
                                                    std::cout << "File was successfully decrypted\n";
                                            }
                                            else
                                                std::cout << "File signature not found\n";
                                        }
                                        CryptDestroyKey(hKey);
                                    }
                                    else
                                        std::cout << "Unable to import key\n";
                                }
                                else
                                    std::cout << "Read error\n";
                                CryptDestroyKey(hPrivKey);
                            }
                            }
                            CryptDestroyHash(hHash);
                        }
                        else
                            std::cout << "Can`t create hash\n";
                        CryptDestroyKey(hPubKey);
                    }
                    else
                        std::cout << "Can`t import key\n";
                }
                else
                    std::cout << "Can`t read file with public key\n";
                CloseHandle(hKeyFile);
            }
            else
                std::cout << "Can`t open file with public key\n";
            CloseHandle(hOutFile);
        }
        else
            std::cout << "Can`t open output file\n";
        CloseHandle(hInFile);
    }
    else
        std::cout << "Can`t open input file\n";
    CryptReleaseContext(hProv, 0);
}
void GenerateKey()
{
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0) && !CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET)){
        std::cout << "Unable to create context\n";
        return;
    }
    DWORD flags = 1024 << 16;
    flags |= CRYPT_EXPORTABLE;
    if (CryptGenKey(hProv, AT_KEYEXCHANGE, flags, &hKey)){
        struct RSAPrivKey1024 key;
        DWORD dwLen = sizeof(struct RSAPrivKey1024);
        if (CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, (BYTE*)&key, &dwLen)) {
            //std::cout << &key.privateExponent << std::endl;
            HANDLE hFile;
            if ((hFile = CreateFileA("key.rsa", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE) {
                if (!WriteFile(hFile, &key, dwLen, &dwLen, NULL))
                    std::cout << "Unable to save RSA key in file\n";
                CloseHandle(hFile);
            }
            else
                std::cout << "Unable to create key file\n";
        }
        else
            std::cout << "Unable to export RSA key\n";
        CryptDestroyKey(hKey);
    }
    else
        std::cout << "Unable to create RSA key\n";
    CryptReleaseContext(hProv, 0);
}

int main(){
    int choise = 0;
    while (choise != -1) {
        std::cout << "1 - Generate Key\n2 - Encode\n3 - Decode\n";
        std::cin >> choise;
        auto start = high_resolution_clock::now();
        switch (choise) {
        case 1: GenerateKey();
            break;
        case 2: ProcessFile("in.bin", "out.bin", "key.rsa", 'e', (BYTE*)"ass");
            break;
        case 3: ProcessFile("out.bin", "out_d.bin", "key.rsa", 'd');
            break;
        }
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<milliseconds>(stop - start);
        std::cout << duration.count()/1000.0 << std::endl;
    }
    ExitProcess(0);
    return 0;
}