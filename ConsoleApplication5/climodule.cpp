#include "climodule.h"
#include <Windows.h>

// 静态成员变量定义
CLIModule::ModuleClassPtr CLIModule::ModulePtr = nullptr;
vector<CLIModule::ModuleClassPtr> CLIModule::moduleclasspointers = vector<CLIModule::ModuleClassPtr>();

CLIModule::CLIModule()
{
}
CLIModule::~CLIModule()
{
}
void CLIModule::RegisterModule(string name, LPVOID classptr, BOOL flag)
{
	ModuleClassPtr newModule = new ModuleClass();
	newModule->Name = name;
	newModule->ClassPtr = classptr;
	newModule->Flag = flag;
	moduleclasspointers.push_back(newModule);
}
LPVOID CLIModule::GetModuleClassPtrByName(string name)
{
	for (auto moduleclassptr:moduleclasspointers) {
		if (moduleclassptr->Name.compare(name)==0) {
			return moduleclassptr->ClassPtr;
		}
	}
	return nullptr;
}
vector<string> CLIModule::GetAllModuleNames()
{
	vector<string> names = vector<string>();
	for (auto moduleclassptr : moduleclasspointers) {
		names.push_back(moduleclassptr->Name);
	}
	return names;
}
