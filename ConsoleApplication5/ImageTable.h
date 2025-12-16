#pragma once
#include <map>
#include <vector>
#include <Windows.h>
#include <string>
using namespace std;
class ImageTableAnalyzer
{
public:
	vector<string> dllList = vector<string>();
	map<string, vector<string>> funcList = map<string, vector<string>>();
	ULONGLONG funcAddress = 0;
	LPVOID lpBuffer = NULL;
	HANDLE hFile = NULL;
	HANDLE hFileMapping = NULL;
public:
	vector<string> AnalyzeTableForDLL(string file);
	map<string, vector<string>> AnalyzeTableForFunctions(string file);
	ULONGLONG GetFuncaddressByName(string name,string file);
	bool IsImagineTable(LPVOID lpBuffer);
	bool IATHooked(string dllfile,int PID);
	int GetPIDByName(wstring processname);
	DWORD RVAtoFOA(DWORD rva, LPVOID lpBuffer);
public:
	ImageTableAnalyzer();
	~ImageTableAnalyzer();
};