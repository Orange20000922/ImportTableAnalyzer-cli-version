#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include <queue>
using namespace std;
class CLIModule
{
public:
	typedef struct ModuleClass{
		BOOL Flag;
		LPVOID ClassPtr;
		string Name;
	}*ModuleClassPtr,ModuleClass;
private:
	static ModuleClassPtr ModulePtr;
	static vector<ModuleClassPtr> moduleclasspointers;
public :
	CLIModule();
	~CLIModule();
	static void RegisterModule(string name, LPVOID classptr,BOOL flag);
	LPVOID GetModuleClassPtrByName(string name);
	vector<string> GetAllModuleNames();
};