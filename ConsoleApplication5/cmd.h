#pragma once
#include <Windows.h>
#include <string>
#include "climodule.h"
#include <queue>
#include <vector>
#include "ImageTable.h"
using namespace std;
class  Command 
{
    protected:
		BOOL FlagHasArgs = false;
		
	public:
		virtual void AcceptArgs(vector<LPVOID> argslist)=0;
		virtual void Execute(string command) = 0;
		virtual BOOL HasArgs() = 0;
};
class PrintAllCommand : public Command
{
public:
	static string name;
public:
	PrintAllCommand();
	void AcceptArgs(vector<LPVOID> argslist) override;
	void Execute(string command) override;
	BOOL HasArgs() override;
	static BOOL CheckName(string input);
	static LPVOID GetInstancePtr() {
		return new PrintAllCommand();
	}
	static string GetName() {
		return name;
	}
};
class HelpCommand : public Command
{
public:
	static string name;
	static vector<LPVOID> ArgsList;
public:
	HelpCommand();
	void AcceptArgs(vector<LPVOID> argslist) override;
	void Execute(string command) override;
	BOOL HasArgs() override;
	static BOOL CheckName(string input);
	static LPVOID GetInstancePtr() {
		return new HelpCommand();
	}
	static string GetName() {
		return name;
	}
};
class QueueDLLsCommand : public Command
{
    public:
	static string name;
	static vector<LPVOID> ArgsList;
	public:
		QueueDLLsCommand();
		~QueueDLLsCommand();
	void AcceptArgs(vector<LPVOID> argslist) override;
	void Execute(string command) override;
	BOOL HasArgs() override;
	static BOOL CheckName(string input);
	static LPVOID GetInstancePtr() {
		return new QueueDLLsCommand();
	}
	static string GetName() {
		return name;
	}
};
class GetProcessFuncAddressCommand : public Command
{
    public:
	static string name;
	static vector<LPVOID> ArgsList;
	public:
	GetProcessFuncAddressCommand();
	~GetProcessFuncAddressCommand();
	void AcceptArgs(vector<LPVOID> argslist) override;
	void Execute(string command) override;
	BOOL HasArgs() override;
	static BOOL CheckName(string input);
	static LPVOID GetInstancePtr() {
		return new GetProcessFuncAddressCommand();
	}
	static string GetName() {
		return name;
	}
};
class IATHookDLLCommand : public Command
{
    public:
	static string name;
	static vector<LPVOID> ArgsList;
	ImageTableAnalyzer* analyzer = new ImageTableAnalyzer();
	public:
	IATHookDLLCommand();
	~IATHookDLLCommand();
	void AcceptArgs(vector<LPVOID> argslist) override;
	void Execute(string command) override;
	BOOL HasArgs() override;
	static BOOL CheckName(string input);
	static LPVOID GetInstancePtr() {
		return new IATHookDLLCommand();
	}
	static string GetName() {
		return name;
	}
};

class ExitCommand : public Command
{
   public:
	static string name;
	static vector<LPVOID> ArgsList;
   public:
		ExitCommand();
	void AcceptArgs(vector<LPVOID> argslist) override;
	void Execute(string command) override;
	BOOL HasArgs() override;
	static BOOL CheckName(string input);
	static LPVOID GetInstancePtr() {
		return new ExitCommand();
	}
	static string GetName() {
		return name;
	}
};
class PrintAllFunction : public Command{
    public:
	 static string name;
	 static vector<LPVOID> Arglist;
	 ImageTableAnalyzer* analyzer = new ImageTableAnalyzer();
   public:
	   PrintAllFunction();
	   ~PrintAllFunction();
	   void AcceptArgs(vector<LPVOID> argslist) override;
	   void Execute(string command) override;
	   BOOL HasArgs() override;
	   static BOOL CheckName(string input);
	   static LPVOID GetInstancePtr() {
		   return new PrintAllFunction();
	   }
	   static string GetName() {
		   return name;
	   }
};
class IATHookByNameCommand :public Command{
public:
	static string name;
	static vector<LPVOID> ArgsList;
	ImageTableAnalyzer* analyzer = new ImageTableAnalyzer();
public:
	IATHookByNameCommand();
	~IATHookByNameCommand();
	void AcceptArgs(vector<LPVOID> argslist) override;
	void Execute(string command) override;
	BOOL HasArgs() override;
	static BOOL CheckName(string input);
	static LPVOID GetInstancePtr() {
		return new IATHookByNameCommand();
	}
	static string GetName() {
		return name;
	}

};
class IATHookByCreateProc :public Command{
	public:
	static string name;
	static vector<LPVOID> ArgsList;
	ImageTableAnalyzer* analyzer = new ImageTableAnalyzer();
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
private:
	static DWORD pid;
public:
	IATHookByCreateProc();
	~IATHookByCreateProc();
	void AcceptArgs(vector<LPVOID> argslist) override;
	void Execute(string command) override;
	BOOL HasArgs() override;
	static BOOL CheckName(string input);
	static LPVOID GetInstancePtr() {
		return new IATHookByCreateProc();
	}
	static string GetName() {
		return name;
	}
	static DWORD GetPID() {
		return pid;
	}
};