#pragma once
#include <Windows.h>
#include <string>
#include "climodule.h"
#include <queue>
#include <vector>
using namespace std;
class  Command 
{
    protected:
		BOOL FlagHasArgs;
	public:
		virtual void AcceptArgs(vector<LPVOID> argslist)=0;
		virtual void Execute() = 0;
		virtual BOOL HasArgs() = 0;
};
