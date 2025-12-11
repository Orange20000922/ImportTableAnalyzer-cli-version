#include "ImageTable.h"
#include <vector>
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>  
#include <map>
#include <sstream>
using namespace std;
DWORD ImageTableAnalyzer::GetFuncaddressByName(string name,string file)
{
	ImageTableAnalyzer::hFile = CreateFileA(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
		cout << "Open file failed!" << endl;
	}
	ImageTableAnalyzer::hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == INVALID_HANDLE_VALUE) {
		CloseHandle(hFileMapping);
		cout << "Create file mapping failed!" << GetLastError() << endl;
		return NULL;
	}
	ImageTableAnalyzer::lpBuffer = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (!IsImagineTable(lpBuffer) ){
		cout << "This is not a valid PE file!" << endl;
		return NULL;
	}
	DWORD peOffset = ((PIMAGE_DOS_HEADER)lpBuffer)->e_lfanew;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpBuffer + peOffset);
	if (pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 || pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64) {
		PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = &pNtHeaders->OptionalHeader;
		DWORD importDirRVA = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		if (importDirRVA == 0) {
			cout << "No import directory!" << endl;
			return NULL;
		}
	    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpBuffer + RVAtoFOA(importDirRVA,lpBuffer));
		auto IAT = (PIMAGE_THUNK_DATA64)((DWORD_PTR)lpBuffer + RVAtoFOA(pImportDescriptor->FirstThunk,lpBuffer));
		while (pImportDescriptor->Name != 0) {
			while (IAT->u1.Ordinal!=0) {
				if ((IAT->u1.AddressOfData & IMAGE_ORDINAL_FLAG64) == 0) {
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpBuffer + RVAtoFOA(IAT->u1.AddressOfData,lpBuffer));
					if (name.compare(string((char*)pImportByName->Name))==0) {
						DWORD ImageBase = pOptionalHeader64->ImageBase;
						funcAddress = (DWORD)(IAT->u1.AddressOfData+ImageBase);
						return funcAddress;
					}
				}
				IAT++;
			}
			pImportDescriptor++;
		}
	}
	return 0;
}

vector<string> ImageTableAnalyzer::AnalyzeTableForDLL(string file)
{
	ImageTableAnalyzer::hFile = CreateFileA(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return vector<string>();
		cout << "Open file failed!" << endl;
	}
	ImageTableAnalyzer::hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping==INVALID_HANDLE_VALUE) {
		CloseHandle(hFileMapping);
		cout << "Create file mapping failed!" << GetLastError() << endl;
		return vector<string>();
	}
	ImageTableAnalyzer::lpBuffer = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (!lpBuffer) {
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return vector<string>();
	}
	if (!IsImagineTable(lpBuffer)) {
		cout << "This is not a valid PE file!" << endl;
		return vector<string>();
	}
	DWORD peOffset = ((PIMAGE_DOS_HEADER)lpBuffer)->e_lfanew;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpBuffer + peOffset);
	if (pNtHeaders->FileHeader.Machine==IMAGE_FILE_MACHINE_AMD64||pNtHeaders->FileHeader.Machine==IMAGE_FILE_MACHINE_ARM64||pNtHeaders->FileHeader.Machine==IMAGE_FILE_MACHINE_I386) {
		PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = &pNtHeaders->OptionalHeader;
		DWORD importDirRVA = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		if (importDirRVA == 0) {
			cout << "No import directory!" << endl;
			return vector<string>();
		}
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpBuffer+RVAtoFOA(importDirRVA, lpBuffer));
		while (pImportDescriptor->Name!=0) {
			char* dllName = (char*)(RVAtoFOA(pImportDescriptor->Name,lpBuffer)+(DWORD_PTR)lpBuffer);
			dllList.push_back(string(dllName));
			pImportDescriptor++;
		}
	}
	else {
		return vector<string>();
	}
    return dllList;
}

map<string, vector<string>> ImageTableAnalyzer::AnalyzeTableForFunctions(string file)
{
	vector<string> funcNames;
	ImageTableAnalyzer::hFile = CreateFileA(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return map<string, vector<string>>();
		cout << "Open file failed!" << endl;
	}
	ImageTableAnalyzer::hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hFileMapping) {
		CloseHandle(hFileMapping);
		cout << "Create file mapping failed!" << GetLastError() << endl;
		return map<string, vector<string>>();
	}
	lpBuffer = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (!lpBuffer) {
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return map<string, vector<string>>();
	}
	if (!IsImagineTable(lpBuffer)) {
		cout << "This is not a valid PE file!" << endl;
		return map<string, vector<string>>();
	}
	DWORD peOffset = ((PIMAGE_DOS_HEADER)lpBuffer)->e_lfanew;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpBuffer + peOffset);
	if (pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 || pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64 || pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = &pNtHeaders->OptionalHeader;
		DWORD importDirRVA = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		if (importDirRVA == 0) {
			cout << "No import directory!" << endl;
			return map<string, vector<string>>();
		}
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpBuffer + RVAtoFOA(importDirRVA,lpBuffer));
		while (pImportDescriptor->Name != 0) {
			char* dllName = (char*)((DWORD_PTR)lpBuffer + RVAtoFOA(pImportDescriptor->Name,lpBuffer));
			auto IAT = (PIMAGE_THUNK_DATA64)((DWORD_PTR)lpBuffer + RVAtoFOA(pImportDescriptor->FirstThunk, lpBuffer));
		    while (IAT->u1.Ordinal!=0){
				if ((IAT->u1.AddressOfData & IMAGE_ORDINAL_FLAG64) == 0) {
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpBuffer + RVAtoFOA(IAT->u1.AddressOfData,lpBuffer));
					funcNames.push_back(string((char*)pImportByName->Name));
				}
				else {
					ostringstream oss;
					oss << "Ordinal:" << (IAT->u1.AddressOfData & 0xFFFF);
					funcNames.push_back(oss.str());
				}
				IAT++;
			}
			funcList[string(dllName)] = funcNames;
			pImportDescriptor++;
		}
	}else {
		return map<string, vector<string>>();
	}
	return funcList;
}

bool ImageTableAnalyzer::IsImagineTable(LPVOID lpBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBuffer;
	if (pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE) {
		return false;
	}
	DWORD peOffset = pDosHeader->e_lfanew;
	if (peOffset<sizeof(IMAGE_DOS_HEADER)||peOffset>GetFileSize(hFile,NULL) ){
		return false;
	}
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpBuffer + peOffset);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}
	return true;
}

bool ImageTableAnalyzer::IATHooked(string dllfile, int PID)
{
	SIZE_T sizedllfilename = 1 + lstrlenA(dllfile.c_str()) * sizeof(TCHAR);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (NULL==hProcess) {
		cout << "Open process failed!" << GetLastError() << endl;
		return false;
	}
	LPVOID lpdlladdr=VirtualAllocEx(hProcess, NULL, sizedllfilename, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	BOOL bRet=WriteProcessMemory(hProcess, NULL, dllfile.c_str(), sizedllfilename, NULL);
	if (!bRet) {
		CloseHandle(hProcess);
		cout << "Write process memory failed!" << GetLastError() << endl;
		return false;
	}
	LPVOID lpFuncAddress = (LPVOID)LoadLibraryA;
	HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpFuncAddress, lpdlladdr, 0, NULL);
	if (NULL==remoteThread) {
		CloseHandle(hProcess);
		return false;
	}
	CloseHandle(remoteThread);
	CloseHandle(hProcess);
	return true;
}
int ImageTableAnalyzer::GetPIDByName(wstring processname)
{
	DWORD PID = 0;
	HANDLE hshapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL,0);
	PROCESSENTRY32* pe ;
	ZeroMemory(&pe,sizeof(PROCESSENTRY32));
	pe->dwSize = sizeof(PROCESSENTRY32);
	Process32First(hshapshot,pe);
	while (Process32Next(hshapshot,pe)) {
		if (processname.compare(pe->szExeFile)==0) {
			PID = pe->th32ProcessID;
			return PID;
		}
	}
	CloseHandle(hshapshot);
	return 0;
}
DWORD ImageTableAnalyzer::RVAtoFOA(DWORD rva, LPVOID lpBuffer)
{
	DWORD peOffset = ((PIMAGE_DOS_HEADER)lpBuffer)->e_lfanew;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpBuffer + peOffset);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		DWORD sectionVA = pSectionHeader[i].VirtualAddress;
		DWORD sectionSize = pSectionHeader[i].Misc.VirtualSize;
		if (rva >= sectionVA && rva < sectionVA + sectionSize) {
			DWORD delta = rva - sectionVA;
			DWORD foa = pSectionHeader[i].PointerToRawData + delta;
			return foa;
		}
	}
	return 0;
}
ImageTableAnalyzer::ImageTableAnalyzer() {
}
ImageTableAnalyzer::~ImageTableAnalyzer() {
	CloseHandle(ImageTableAnalyzer::hFileMapping);
	CloseHandle(ImageTableAnalyzer::hFile);
	UnmapViewOfFile(lpBuffer);
}
