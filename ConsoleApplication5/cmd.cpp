#include "cmd.h"
#include <vector>
#include <iostream>
#include <Windows.h>
#include <queue>
#include "cli.h"
using namespace std;
	 vector<LPVOID> HelpCommand::ArgsList = vector<LPVOID>();
	 vector<LPVOID> QueueDLLsCommand::ArgsList = vector<LPVOID>();
	 vector<LPVOID> GetProcessFuncAddressCommand::ArgsList = vector<LPVOID>();
	 vector<LPVOID> IATHookDLLCommand::ArgsList = vector<LPVOID>();
	 vector<LPVOID> ExitCommand::ArgsList = vector<LPVOID>();
     PrintAllCommand::PrintAllCommand() {
		FlagHasArgs = FALSE;
     }
    void PrintAllCommand::AcceptArgs(vector<LPVOID> argslist){
		// This command does not accept any arguments
    }
	BOOL PrintAllCommand::CheckName(string input)
	{
		if (input.compare(name)==0) {
			return true;
		}
		return false;
	}
    void PrintAllCommand::Execute(string command) {
		if (!CheckName(command)) {
			return;
		}
		vector<queue<string>> allCommands = CLI::GetCommands();
		for (auto& cmdQueue : allCommands) {
			string output = "";
			queue<string> tempQueue = cmdQueue;
			int count = 0;
			int size = tempQueue.size();// Create a copy to preserve the original
			while (!tempQueue.empty()) {
				if (count<size) {
					output += tempQueue.front() + " ";
					tempQueue.pop();
				}
				else {
					output += tempQueue.front();
					tempQueue.pop();
				}
				count++;
			}
			cout << output << endl;
		}
    }
    BOOL PrintAllCommand::HasArgs()  {
		return FlagHasArgs;
    }
    HelpCommand::HelpCommand() {
		FlagHasArgs = TRUE;
    }
	void HelpCommand::AcceptArgs(vector<LPVOID> argslist)  {
		HelpCommand::ArgsList = argslist;
	}
	void HelpCommand::Execute(string command)  {
		if (!CheckName(command)) {
			return;
		}
		vector<string> currectcommands = vector<string>();
		cout << "Available args:" << endl;
		cout << "|file is the place where you put the file you want to analyze" << endl;
		cout << "|pid is the place where you put process id" << endl;
		cout << "|name is the place where you put function name all process name" << endl;
		if (ArgsList.size()==1) {
			for (auto command : CLI::GetCommands()) {
				if (command.front().compare(*(string*)ArgsList[0]) == 0) {
					string currectcommand = "";
					while (!command.empty()) {
						currectcommand += command.front() + " ";
						currectcommands.push_back(currectcommand);
						command.pop();
					}
				}
			}
			for (auto command:currectcommands) {
				cout << command << endl;
			}
		}
		else {
			return;
		}
	}
	BOOL HelpCommand::HasArgs(){
		return FlagHasArgs;
	}
	BOOL HelpCommand::CheckName(string input)
	{
		if (input.compare(name) == 0) {
			return true;
		}
		return false;
	}
	QueueDLLsCommand::QueueDLLsCommand()
	{
		
		FlagHasArgs = TRUE;
	}
	QueueDLLsCommand::~QueueDLLsCommand()
	{
	}
	void QueueDLLsCommand::AcceptArgs(vector<LPVOID> theargslist)
	{
		QueueDLLsCommand::ArgsList = theargslist;
	}
	void QueueDLLsCommand::Execute(string command)
	{
		if (!CheckName(command)) {
			return;
		}
		ImageTableAnalyzer* analyzer = new ImageTableAnalyzer();
		if (ArgsList.size()!=1) {
			cout << "Invaild Args!" << endl;
		}
		else {
			string& pefile = *(string*)ArgsList[0];
			vector<string> dlllist = analyzer->AnalyzeTableForDLL(pefile);
			if (dlllist.size() != 0) {
				for (int i = 0; i < dlllist.size(); i++) {
					cout << dlllist[i] << endl;
				}
			}
			else {
				cout << "can't find the IAT" << endl;
			}
		}
		delete analyzer;
	}

	BOOL QueueDLLsCommand::HasArgs()
	{
		return TRUE;
	}

	BOOL QueueDLLsCommand::CheckName(string input)
	{
		if (input.compare(name) == 0) {
			return true;
		}
		return false;
	}

	GetProcessFuncAddressCommand::GetProcessFuncAddressCommand()
	{
		FlagHasArgs = TRUE;
	}
	GetProcessFuncAddressCommand::~GetProcessFuncAddressCommand()
	{
	}
	void GetProcessFuncAddressCommand::AcceptArgs(vector<LPVOID> argslist)
	{
		GetProcessFuncAddressCommand::ArgsList = argslist;
	}
	void GetProcessFuncAddressCommand::Execute(string command)
	{
		if (!CheckName(command)) {
			return;
		}
		ImageTableAnalyzer* analyzer = new ImageTableAnalyzer();
		if (ArgsList.size() != 2) {
			cout << "Invaild Args!" << endl;
		}
		else {
			string& funcname = *(string*)ArgsList[1];
			string& pefile = *(string*)ArgsList[0];
			ULONGLONG funcaddress = analyzer->GetFuncaddressByName(funcname, pefile);
			if (funcaddress != 0) {
				cout << "Function Address: 0x" << hex << funcaddress << endl;
			}
			else {
				cout << "can't find the function address" << endl;
			}
		}
		delete analyzer;
	}
	BOOL GetProcessFuncAddressCommand::HasArgs()
	{
		return FlagHasArgs;
	}
	BOOL GetProcessFuncAddressCommand::CheckName(string input)
	{
		if (input.compare(name) == 0) {
			return true;
		}
		return false;
	}
	IATHookDLLCommand::IATHookDLLCommand()
	{
		FlagHasArgs = TRUE;
	}
	IATHookDLLCommand::~IATHookDLLCommand()
	{
	}
	void IATHookDLLCommand::AcceptArgs(vector<LPVOID> argslist)
	{
		IATHookDLLCommand::ArgsList = argslist;
	}
	void IATHookDLLCommand::Execute(string command)
	{
		if (!CheckName(command)) {
			return;
		}
		ImageTableAnalyzer* analyzer = new ImageTableAnalyzer();
		if (ArgsList.size() != 2) {
			cout << "Invaild Args!" << endl;
			delete analyzer;
			return;
		}
		else {
			string& dllfile = *(string*)ArgsList[0];
			string& processname = *(string*)ArgsList[1];
			int size_need = MultiByteToWideChar(CP_UTF8,0,processname.c_str(),(int)processname.size(),NULL,0);
			wstring wprocessname(size_need, 0);
			MultiByteToWideChar(CP_UTF8, 0, processname.c_str(), (int)processname.size(), wprocessname.data(), size_need);
			bool result = analyzer->IATHooked(dllfile, analyzer->GetPIDByName(wprocessname));
			if (result) {
				cout << "IAT Hooked successfully!" << endl;
			}
			else {
				cout << "IAT Hook failed!" << endl;
			}
		}
		delete analyzer;
	}
	BOOL IATHookDLLCommand::HasArgs()
	{
		return TRUE;
	}
	BOOL IATHookDLLCommand::CheckName(string input)
	{
		if (input.compare(name) == 0) {
			return true;
		}
		return false;
	}

	ExitCommand::ExitCommand()
	{
		FlagHasArgs = FALSE;
	}
	void ExitCommand::AcceptArgs(vector<LPVOID> argslist)
	{
	}
	void ExitCommand::Execute(string command)
	{
		if (!CheckName(command)) {
			return;
		}
		cout << "Exiting the application." << endl;
		exit(0);
	}
	BOOL ExitCommand::HasArgs()
	{
		return FlagHasArgs;
	}

	BOOL ExitCommand::CheckName(string input)
	{
		if (input.compare(name) == 0) {
			return true;
		}
		return false;
	}
