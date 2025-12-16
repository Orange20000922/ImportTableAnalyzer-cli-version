#include "cmd.h"
#include <vector>
#include <iostream>
#include <Windows.h>
using namespace std;
class PrintAllCommand : public Command
{
	public:
	PrintAllCommand() {
		FlagHasArgs = FALSE;
	}
	void AcceptArgs(vector<LPVOID> argslist) override {
		// This command does not accept any arguments
	}
	void Execute() override {
		
		MessageBox(nullptr, L"Executing PrintAllCommand", L"Info", MB_OK);
	}
	BOOL HasArgs() override {
		return FlagHasArgs;
	}
};


