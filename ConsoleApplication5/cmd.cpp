#include "cmd.h"
#include <vector>
#include <iostream>
#include <Windows.h>
#include <queue>
#include "cli.h"
#include "ImageTable.h"
using namespace std;
	 vector<LPVOID> HelpCommand::ArgsList = vector<LPVOID>();
	 vector<LPVOID> QueueDLLsCommand::ArgsList = vector<LPVOID>();
	 vector<LPVOID> GetProcessFuncAddressCommand::ArgsList = vector<LPVOID>();
	 vector<LPVOID> IATHookDLLCommand::ArgsList = vector<LPVOID>();
	 vector<LPVOID> ExitCommand::ArgsList = vector<LPVOID>();
	 vector<LPVOID> PrintAllFunction::Arglist = vector<LPVOID>();
	 vector<LPVOID> IATHookByNameCommand::ArgsList = vector<LPVOID>();
	 vector<LPVOID> IATHookByCreateProc::ArgsList = vector<LPVOID>();
	 DWORD IATHookByCreateProc::pid = 0;
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
		cout << "|name is the place where you put function name or process name" << endl;
		if (ArgsList.size()==1) {
			for (auto command : CLI::GetCommands()) {
				if (command.front().compare(*(string*)ArgsList[0]) == 0) {
					if (command.front().compare("IATHook") == 0) {
						cout << "    "<<"For the subcommand 'IATHook |file |file',the first |file means dll's file,the next means object process file" << endl;
					}
					string currectcommand = "";
					while (!command.empty()) {
						currectcommand += command.front() + " ";
						command.pop();
					}
					currectcommands.push_back(currectcommand);
				}
			}
			for (auto command:currectcommands) {
				cout << "    "+command << endl;
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
					cout << "    "+dlllist[i] << endl;
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
		delete analyzer;
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
		if (ArgsList.size() != 2) {
			cout << "Invaild Args!" << endl;
			delete analyzer;
			return;
		}
		else {
			string& dllfile = *(string*)ArgsList[0];
			string& pid = *(string*)ArgsList[1];
			try {
				bool result = analyzer->IATHooked(dllfile, stoi(pid));
				if (result) {
					cout << "IAT Hooked successfully!" << endl;
				}
				else {
					cout << "IAT Hook failed!" << endl;
				}
			}catch(std::invalid_argument&){
				cout << "Invaild PID!" << endl;
			}
		}
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
		DWORD pid = IATHookByCreateProc::GetPID();
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
		if (hProcess!=NULL) {
			TerminateProcess(hProcess, 0);
			CloseHandle(hProcess);
		}
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
	PrintAllFunction::PrintAllFunction()
	{
		FlagHasArgs = true;
	}

	PrintAllFunction::~PrintAllFunction()
	{
		delete analyzer;
	}
	void PrintAllFunction::AcceptArgs(vector<LPVOID> argslist)
	{
		PrintAllFunction::Arglist = argslist;
	}
	void PrintAllFunction::Execute(string command)
	{
		if (Arglist.size()==1) {
			string file = *(string*)Arglist[0];
			map<string,vector<string>> funclist = analyzer->AnalyzeTableForFunctions(file);
			vector<string> dllNames = analyzer->AnalyzeTableForDLL(file);
			for (auto dllName :dllNames) {
				vector<string> value = funclist[dllName];
				cout << dllName + ":" << endl;
				for (auto funcname:value) {
					ULONGLONG funcaddr = analyzer->GetFuncaddressByName(funcname,file);
					cout << "    " + funcname +"  " +"FunctionAddress:" +"0x" << hex << funcaddr << endl;
				}
			}
		}
	}
	BOOL PrintAllFunction::HasArgs()
	{
		return FlagHasArgs;
	}
	BOOL PrintAllFunction::CheckName(string input)
	{
		if (input.compare(name) == 0) {
			return true;
		}
		return false;
	}
	IATHookByNameCommand::IATHookByNameCommand()
	{
		FlagHasArgs = true;
	}
	IATHookByNameCommand::~IATHookByNameCommand()
	{
		delete analyzer;
	}
	void IATHookByNameCommand::AcceptArgs(vector<LPVOID> argslist)
	{
		ArgsList = argslist;
	}
	void IATHookByNameCommand::Execute(string command)
	{
		if (!CheckName(command)) {
			return;
		}
		if (ArgsList.size() != 2) {
			cout << "Invaild Args!" << endl;
			delete analyzer;
			return;
		}
		else {
			string& dllfile = *(string*)ArgsList[0];
			string& processname = *(string*)ArgsList[1];
			int size_need = MultiByteToWideChar(CP_UTF8, 0, processname.c_str(), (int)processname.size(), NULL, 0);
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
	}
	BOOL IATHookByNameCommand::HasArgs()
	{
		return FlagHasArgs;
	}
	BOOL IATHookByNameCommand::CheckName(string input)
	{
		if (input.compare(name) == 0) {
			return true;
		}
		return false;
	}

	IATHookByCreateProc::IATHookByCreateProc()
	{
		FlagHasArgs = true;
	}
	IATHookByCreateProc::~IATHookByCreateProc()
	{
		delete analyzer;
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	void IATHookByCreateProc::AcceptArgs(vector<LPVOID> argslist)
	{
		ArgsList = argslist;
	}
	void IATHookByCreateProc::Execute(string command)
	{
		if (!CheckName(command)) {
			return;
		}
		if (ArgsList.size() != 2) {
			cout << "Invaild Args!" << endl;
			delete analyzer;
			return;
		}
		else {
			string& dllfile = *(string*)ArgsList[0];
			string& processfile = *(string*)ArgsList[1];
			//处理中文路径
			int size_need = MultiByteToWideChar(CP_UTF8, 0, processfile.c_str(), (int)processfile.size(), NULL, 0);
			wstring wprocessfile(size_need, 0);
			MultiByteToWideChar(CP_UTF8, 0, processfile.c_str(), (int)processfile.size(), wprocessfile.data(), size_need);
			cout << "Creating process: " << processfile << endl;
			ZeroMemory(&si, sizeof(si));
			ZeroMemory(&pi, sizeof(pi));
			BOOL flag = CreateProcessW(
				wprocessfile.c_str(),
				NULL,
				NULL,
				NULL,
				FALSE,
				CREATE_NEW_CONSOLE,
				NULL,
				NULL,
				&si,
				&pi
			);
			if (flag) {
				pid = pi.dwProcessId;
				bool result = analyzer->IATHooked(dllfile, pi.dwProcessId);
				if (result) {
					cout << "IAT Hooked successfully!" << endl;
				}
				else {
					cout << "IAT Hook failed!" <<GetLastError()<< endl;
				}
			}
			else {
				cout << "Create Process Failed!" << endl;
			}
		}
	}
	BOOL IATHookByCreateProc::HasArgs()
	{
		return FlagHasArgs;
	}
	BOOL IATHookByCreateProc::CheckName(string input)
	{
		if (input.compare(name) == 0) {
			return true;
		}
		return false;
	}
