/*************************************************************************
** sample_hook.c
** Author: Juan Caballero <jcaballero@cmu.edu>
**
** This file contains a sample hook for the getsockname function
**
*/

extern "C"
{
#include "config.h"
#include "plugin.h"
#include "group_hook_helper.h"
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
//#ifdef PLUGIN_TRACECAP
//  #include "../../../tracecap/my_stub_def.h"
//  #include "../../../tracecap/tracecap.h"
//#else
#include <time.h>
extern "C"
{
#include "shared/procmod.h" //MIKE: find_procname, it is provided by temu
  extern uint32_t tracepid;
  extern int is_tracing;
  extern int tracing_start(uint32_t pid, const char *filename);
  extern void internal_init_plugin(); // "C"
  typedef struct {
    uint32_t source;
    uint32_t origin;
    uint32_t offset;
  } hook_taint_record_t;
  #define TAINT_SOURCE_API_SOCK_INFO_IN 9
}
  #include "sample_helper.h" //MIKE: C++ utilities
//#endif

typedef enum {NONZERO, HANDLE, REG} succeed_t;

#define LOCAL_DEBUG 1
#define WRITE if (LOCAL_DEBUG) write_log

/* Taint origin used when tainting output of the function */ 
#define GETSOCKNAME_ORIGIN 1105

/* Function prototypes */
//static int getsockname_call(void *opaque);
//static int getsockname_ret(void *opaque);

// --- library
int LoadLibrary_call(void *opaque);
int LoadLibrary_ret(void *opaque);

// --- process & thread
int CreateProcessInternal_call(void *opaque);
int CreateProcessInternal_ret(void *opaque);
int CreateProcess_call(void *opaque);
int CreateProcess_ret(void *opaque);
int OpenProcess_call(void *opaque);
int OpenProcess_ret(void *opaque);
int ExitProcess_call(void *opaque);
int TerminateProcess_call(void *opaque);
int WinExec_call(void *opaque);
int WinExec_ret(void *opaque);
int CreateRemoteThread_call(void *opaque);
int CreateRemoteThread_ret(void *opaque);
int OpenThread_call(void *opaque);
int OpenThread_ret(void *opaque);
int CreateThread_call(void *opaque);
int CreateThread_ret(void *opaque);
int TerminateThread_call(void *opaque);
int TerminateThread_ret(void *opaque);

// --- handle
int CloseHandle_call(void *opaque);
int CloseHandle_ret(void *opaque);

// --- file
int CopyFile_call(void *opaque);
int CopyFile_ret(void *opaque);
int CreateFile_call(void *opaque);
int CreateFile_ret(void *opaque);
int WriteFile_call(void *opaque);
int WriteFile_ret(void *opaque);
int ReadFile_call(void *opaque);
int ReadFile_ret(void *opaque);
int DeleteFile_call(void *opaque);
int DeleteFile_ret(void *opaque);

// --- registry
int RegOpenCurrentUser_call(void *opaque);
int RegOpenCurrentUser_ret(void *opaque);
int RegOpenKeyEx_call(void *opaque);
int RegOpenKeyEx_ret(void *opaque);
int RegQueryValueEx_call(void *opaque);
int RegQueryValueEx_ret(void *opaque);
int RegEnumValue_call(void *opaque);
int RegEnumValue_ret(void *opaque);
int RegCloseKey_call(void *opaque);
int RegCloseKey_ret(void *opaque);
int RegSetValue_call(void *opaque);
int RegSetValue_ret(void *opaque);
int RegSetValueEx_call(void *opaque);
int RegSetValueEx_ret(void *opaque);
int RegCreateKey_call(void *opaque);
int RegCreateKey_ret(void *opaque);
int RegCreateKeyEx_call(void *opaque);
//int RegCreateKeyEx_ret(void *opaque); //MIKE: use RegCreateKey_ret
int RegDeleteKey_call(void *opaque);
int RegDeleteKey_ret(void *opaque);

// --- network
int WinHttpConnect_call(void *opaque);
int WinHttpConnect_ret(void *opaque);
int WinHttpCreateUrl_call(void *opaque);
int WinHttpCreateUrl_ret(void *opaque);
int WinHttpOpen_call(void *opaque);
int WinHttpOpen_ret(void *opaque);
int WinHttpOpenRequest_call(void *opaque);
int WinHttpOpenRequest_ret(void *opaque);
int WinHttpReadData_call(void *opaque);
int WinHttpReadData_ret(void *opaque);
int WinHttpSendRequest_call(void *opaque);
int WinHttpSendRequest_ret(void *opaque);
int WinHttpWriteData_call(void *opaque);
int WinHttpWriteData_ret(void *opaque);
int WinHttpGetProxyForUrl_call(void *opaque);
int WinHttpGetProxyForUrl_ret(void *opaque);
int InternetOpen_call(void *opaque);
int InternetOpen_ret(void *opaque);
int InternetConnect_call(void *opaque);
int InternetConnect_ret(void *opaque);
int HttpSendRequest_call(void *opaque);
int HttpSendRequest_ret(void *opaque);
int GetUrlCacheEntryInfo_call(void *opaque);
int GetUrlCacheEntryInfo_ret(void *opaque);

// --- utility
//MIKE: C code is implemented in this file, c++ code is in hook_helper.h
void addr2str(uint32_t addr, int size, char* str);
int print_Eax(succeed_t succeed);
uint32_t print_procInfo(uint32_t pInfo); // return the new spawn process's id
void print_procAccess(uint32_t access);
void print_fileAccess(uint32_t access);
void print_fileDisopsition(uint32_t disposition);
void hkey2str(uint32_t hkey, char* str);
void print_regData(int dwtype, int dwLen, uint32_t lpData);

/* Add here the functions to hook by name 
 * The same hook can be reused for different functions */
hook_t hooks[] =
{
  /*example*/
 // {"ws2_32.dll", "getsockname", getsockname_call, 0},
 // {"wsock32.dll", "getsockname", getsockname_call, 0},

// Library
  {(char*)"kernel32.dll", (char*)"LoadLibraryA", LoadLibrary_call, 0},
  {(char*)"kernel32.dll", (char*)"LoadLibraryW", LoadLibrary_call, 0},

// Process
  {(char*)"kernel32.dll", (char*)"CreateProcessA", CreateProcess_call, 0},
  {(char*)"kernel32.dll", (char*)"CreateProcessW", CreateProcess_call, 0},
  {(char*)"kernel32.dll", (char*)"CreateProcessInternalA", CreateProcessInternal_call, 0},
  {(char*)"kernel32.dll", (char*)"CreateProcessInternalW", CreateProcessInternal_call, 0},
  {(char*)"kernel32.dll", (char*)"OpenProcess", OpenProcess_call, 0},
  {(char*)"kernel32.dll", (char*)"ExitProcess", ExitProcess_call, 0},
  {(char*)"kernel32.dll", (char*)"TerminateProcess", TerminateProcess_call, 0},
  {(char*)"kernel32.dll", (char*)"WinExec", WinExec_call, 0},
  {(char*)"kernel32.dll", (char*)"CreateRemoteThread", CreateRemoteThread_call, 0},
  {(char*)"kernel32.dll", (char*)"OpenThread", OpenThread_call, 0},
  {(char*)"kernel32.dll", (char*)"CreateThread", CreateThread_call, 0},
  {(char*)"kernel32.dll", (char*)"TerminateThread", TerminateThread_call, 0},

// Handle
  {(char*)"kernel32.dll", (char*)"CloseHandle", CloseHandle_call, 0},

// File
  //{(char*)"kernel32.dll", (char*)"CopyFileW", CopyFile_call, 0},
  //{(char*)"kernel32.dll", (char*)"CopyFileA", CopyFile_call, 0},
  {(char*)"kernel32.dll", (char*)"CopyFileExW", CopyFile_call, 0},
  {(char*)"kernel32.dll", (char*)"CopyFileExA", CopyFile_call, 0},
  {(char*)"kernel32.dll", (char*)"CreateFileA", CreateFile_call, 0},
  {(char*)"kernel32.dll", (char*)"CreateFileW", CreateFile_call, 0},
  {(char*)"kernel32.dll", (char*)"WriteFile", WriteFile_call, 0},
  {(char*)"kernel32.dll", (char*)"WriteFileEx", WriteFile_call, 0},
  {(char*)"kernel32.dll", (char*)"ReadFile", ReadFile_call, 0},
  {(char*)"kernel32.dll", (char*)"ReadFileEx", ReadFile_call, 0},
  {(char*)"kernel32.dll", (char*)"DeleteFileW", DeleteFile_call, 0},
  {(char*)"kernel32.dll", (char*)"DeleteFileA", DeleteFile_call, 0},

// Registry
  {(char*)"advapi32.dll", (char*)"RegOpenCurrentUser", RegOpenCurrentUser_call, 0},
  {(char*)"advapi32.dll", (char*)"RegQueryValueExA", RegQueryValueEx_call, 0},
  {(char*)"advapi32.dll", (char*)"RegQueryValueExW", RegQueryValueEx_call, 0},
  {(char*)"advapi32.dll", (char*)"RegEnumValueA", RegEnumValue_call, 0},
  {(char*)"advapi32.dll", (char*)"RegEnumValueW", RegEnumValue_call, 0},
  {(char*)"advapi32.dll", (char*)"RegOpenKeyExA", RegOpenKeyEx_call, 0},
  {(char*)"advapi32.dll", (char*)"RegOpenKeyExW", RegOpenKeyEx_call, 0},
  {(char*)"advapi32.dll", (char*)"RegCloseKey", RegCloseKey_call, 0},
  // {(char*)"advapi32.dll", (char*)"RegSetValueA", RegSetValue_call, 0},
  // {(char*)"advapi32.dll", (char*)"RegSetValueW", RegSetValue_call, 0},
  {(char*)"advapi32.dll", (char*)"RegSetValueExA", RegSetValueEx_call, 0},
  {(char*)"advapi32.dll", (char*)"RegSetValueExW", RegSetValueEx_call, 0},
  //{(char*)"advapi32.dll", (char*)"RegCreateKeyA", RegCreateKey_call, 0},
  //{(char*)"advapi32.dll", (char*)"RegCreateKeyW", RegCreateKey_call, 0},
  {(char*)"advapi32.dll", (char*)"RegCreateKeyExA", RegCreateKeyEx_call, 0},
  {(char*)"advapi32.dll", (char*)"RegCreateKeyExW", RegCreateKeyEx_call, 0},
  {(char*)"advapi32.dll", (char*)"RegDeleteKeyA", RegDeleteKey_call, 0},
  {(char*)"advapi32.dll", (char*)"RegDeleteKeyW", RegDeleteKey_call, 0},
  {(char*)"advapi32.dll", (char*)"RegDeleteValueA", RegDeleteKey_call, 0},
  {(char*)"advapi32.dll", (char*)"RegDeleteValueW", RegDeleteKey_call, 0},

//network : Maintained by Shih Hsuan Li
  {(char*)"winhttp.dll", (char*)"WinHttpConnect", WinHttpConnect_call, 0},
  {(char*)"winhttp.dll", (char*)"WinHttpCreateUrl", WinHttpCreateUrl_call, 0},
  {(char*)"winhttp.dll", (char*)"WinHttpOpen", WinHttpOpen_call, 0},
  {(char*)"winhttp.dll", (char*)"WinHttpOpenRequest", WinHttpOpenRequest_call, 0},
  {(char*)"winhttp.dll", (char*)"WinHttpReadData", WinHttpReadData_call, 0},
  {(char*)"winhttp.dll", (char*)"WinHttpSendRequest", WinHttpSendRequest_call, 0},
  {(char*)"winhttp.dll", (char*)"WinHttpWriteData", WinHttpWriteData_call, 0},
  {(char*)"winhttp.dll", (char*)"WinHttpGetProxyForUrl", WinHttpGetProxyForUrl_call, 0},
  {(char*)"wininet.dll", (char*)"InternetOpenA", InternetOpen_call, 0},
  {(char*)"wininet.dll", (char*)"InternetOpenW", InternetOpen_call, 0},
  {(char*)"wininet.dll", (char*)"InternetConnectA", InternetConnect_call, 0},
  {(char*)"wininet.dll", (char*)"InternetConnectW", InternetConnect_call, 0},
  {(char*)"wininet.dll", (char*)"HttpSendRequestA", HttpSendRequest_call, 0},
  {(char*)"wininet.dll", (char*)"HttpSendRequestW", HttpSendRequest_call, 0},
  {(char*)"wininet.dll", (char*)"GetUrlCacheEntryInfoA", GetUrlCacheEntryInfo_call, 0},
  {(char*)"wininet.dll", (char*)"GetUrlCacheEntryInfoW", GetUrlCacheEntryInfo_call, 0},

};

int local_num_funs = (sizeof(hooks)/sizeof(hook_t));


/* Initialization function */
void internal_init_plugin()
{
  initialize_plugin(hooks,local_num_funs);
  fprintf(stdout, "internal_init_plugin\n");
}

/* Structure that is passed between the call and return hook */
typedef struct {
  uint32_t eip;
  uint32_t hook_handle;
  uint32_t sd;
  uint32_t bufStart;
  uint32_t bufMaxLen;
  uint32_t bufLenPtr;
} getsockname_t;

/* Library Struct */

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t lpFileName;
} loadlibrary_t;

/* Process Struct */

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t lpApplicationName;
  uint32_t lpCommandLine;
  uint32_t lpProcessInformation;
} createprocess_t;

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t dwDesiredAccess;
  uint32_t dwProcessId;
} openprocess_t;

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t lpCmdLine;
} winexec_t;

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t hProcess;
} createremotethread_t;

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t dwThreadId;
} openthread_t;

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t hThread;
} terminatethread_t;

/* Handle Struct */

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t hObject;
} closehandle_t;

/* File Struct */

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t hName;
  uint32_t DesiredAccess;
  uint32_t ShareMode;
  //uint32_t SecurityAttributes;
  uint32_t CreationDisposition;
  //uint32_t FlagsAndAttributes;
  //uint32_t TemplateFile;
} createfile_t;

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t lpExistingFileName;
  uint32_t lpNewFileName;
} copyfile_t;

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t hFile; // MIKE: sometimes it stores the address of the filename string, depend on different API
} rwdfile_t;

/* Registry Struct */

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t hKey;
  uint32_t lpSubKey;
  uint32_t phkresult;
} regopenkey_t;

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t hKey;
  uint32_t lpValueName;
  uint32_t lpcchValueName;
  uint32_t lpType;
  uint32_t lpData;
  uint32_t lpcbData;
} regqueryvalue_t;

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t hKey;
  uint32_t lpSubKey;
  uint32_t dwType;
  uint32_t lpData;
  uint32_t cbData;
} regsetvalue_t;

typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t hKey;
  uint32_t lpSubKey;
  uint32_t lpValueName;
  uint32_t dwType;
  uint32_t lpData;
  uint32_t cbData;
} regsetkeyvalue_t;

/* Networking Struct */
typedef struct {
  uint32_t hook_handle;
  clock_t tick;
  uint32_t url;
} winhttpconnect_t;


/* Call hook (executed before any instruction in the function) */
// static int getsockname_call(void *opaque)
// {
//   uint32_t esp;
//   uint32_t eip;
//   uint32_t buf[7]; // Assumes that all stack parameters are 4-byte long
//   int read_err = 0;

//   /* If not tracing yet, return */
//   if (tracepid == 0) return 0;

//   /* Read stack starting at ESP */
//   read_reg(esp_reg, &esp);
//   read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
//   if (read_err) return 0;

//   /*
//       BUF INDEX -> PARAMETER
//       ws2_32.dll getsockname
//       int getsockname(SOCKET s,struct sockaddr* name,int* namelen);
//       0 -> return address
//       1 -> IN socket descriptor
//       2 -> OUT Address structure with socket information
//       3 -> IN-OUT On call, size of the name buffer, in bytes.
//         On return, size in bytes of the name parameter
//   */

//   /* Check which function we are jumping to */
//   read_reg(eip_reg, &eip);
//   char mod_name[512];
//   char fun_name[512];
//   get_function_name(eip,(char *)&mod_name,(char *)&fun_name);

//   /* Print some information to monitor */
//   WRITE("tracenetlog","Getting socket info using function %s::%s\n"
//     "\tFD: %u BufStart: 0x%08x BufMaxLen: %d\n",
//     mod_name, fun_name,buf[1],buf[2],(int)buf[3]);

//   /* Store parameters so that they can be used by return hook */
//   getsockname_t *s = (getsockname_t*)malloc(sizeof(getsockname_t));
//   if (s == NULL) return 0;
//   s->eip = eip;
//   s->sd = buf[1];
//   s->bufStart = buf[2];
//   s->bufMaxLen = buf[3];
//   s->bufLenPtr = esp+12;

//   /* Hook return of function */
//   s->hook_handle = hookapi_hook_return(buf[0], getsockname_ret, s,
//     sizeof(getsockname_t));

//   return 0;
// }

// /* Return hook (executed after the return instruction) */
// static int getsockname_ret(void *opaque)
// {
//   static int offset  = 0;
//   int read_err = 0;
//   uint32_t bufRealLen = 0;
//   getsockname_t *s = (getsockname_t *)opaque;
//   struct sockaddr_in addrData;
//   char addrStr[INET_ADDRSTRLEN];

//   /* Remove return hook */
//   hookapi_remove_hook(s->hook_handle);

//   /* Check return value -> status */
//   uint32_t eax = 0;
//   read_reg(eax_reg, &eax);
//   if (eax != 0) return 0;

//   /* Read size of address structure */
//   read_err = read_mem(s->bufLenPtr, 4, (unsigned char*)&bufRealLen);
//   if (!read_err) {
//     WRITE ("tracenetlog","\tNumBytesWritten: %u\n",bufRealLen);
//   }
//   else {
//     WRITE ("tracenetlog","\tCould not get number of bytes written\n");
//     return 0;
//   }

//   /* Read the address structure */
//   read_err = read_mem(s->bufStart, 16, (unsigned char*)&addrData);
//   if (read_err) return 0;

//   /* Print the address structure */
//   inet_ntop(AF_INET, &addrData.sin_addr, addrStr, sizeof(addrStr));
//   WRITE ("tracenetlog","\tFamily: %d Port: %u Address: %s\n",
//    addrData.sin_family,ntohs(addrData.sin_port),addrStr);

//   /* Taint address structure */
//   if (bufRealLen > 0) {
//     hook_taint_record_t tr;
//     tr.source = TAINT_SOURCE_API_SOCK_INFO_IN;
//     tr.origin = GETSOCKNAME_ORIGIN;
//     tr.offset = offset;

//     taint_mem(s->bufStart+2, 6, (void *)&tr);
//   }

//   /* Increment the taint offset */
//   offset += 6;

//   /* Free structure used to pass info between call and return hooks */
//   if (s) free(s);

//   return 0;
// }

//======== utilities ==========

void addr2str(uint32_t addr, int size, char* outstr)
{
  char bf[size], temp[size/2];
  int j, k = 0;
  char temp2[size+1]; 

  for(j=0;j<size;j++) bf[j]='\0';
  read_mem(addr, size, (unsigned char*)bf);

  if(bf[1]=='\0' && bf[3]=='\0')//for UTF-16 (wchar in windows)
  {
	for(j=0;j<size;j+=2)
	{
		if(bf[j]=='\0' && bf[j+1]=='\0') break;
		if(bf[j+1]=='\0')
		{
			temp[k]=bf[j];
			k++;
		}
	}
	temp[k]='\0';
	strcpy(outstr, temp);
  }
  else
  {
	for(j=0;j<size;j++)
		temp2[j]=bf[j];
	temp2[j]='\0';
	strcpy(outstr, temp2);
  }
}

void hkey2str(uint32_t hkey, char* str)
{
  switch(hkey)
  {
    case 0x80000000:
      strcpy(str,"HKEY_CLASSES_ROOT");
      break;
    case 0x80000001:
      strcpy(str,"HKEY_CURRENT_USER");
      break;
    case 0x80000002:
      strcpy(str,"HKEY_LOCAL_MACHINE");
      break;
    case 0x80000003:
      strcpy(str,"HKEY_USERS");
      break;
    case 0x80000004:
      strcpy(str,"HKEY_PERFORMANCE_DATA");
      break;
    case 0x80000005:
      strcpy(str,"HKEY_CURRENT_CONFIG");
      break;
    case 0x80000006:
      strcpy(str,"HKEY_DYN_DATA");
      break;
    default:
      string hName = "";
      find_proc_handle(hkey, &hName);
      strcpy(str, hName.c_str());
  }
}

void print_regData(int dwtype, int dwLen, uint32_t lpData)
{
/* Registry Key Value Types:
	0 REG_NONE 
	1 REG_SZ			char* 
	2 REG_EXPAND_SZ  
	3 REG_BINARY  
	4 REG_DWORD			32-bits int (unsigned long)
	4 REG_DWORD_LITTLE_ENDIAN	32-bits int (unsigned long)
	5 REG_DWORD_BIG_ENDIAN 
	6 REG_LINK 
	7 REG_MULTI_SZ			char* ("sz1\0sz2\0sz3\0\0") 
	8 REG_RESOURCE_LIST
	9 REG_FULL_RESOURCE_DESCRIPTOR
	10 REG_RESOURCE_REQUIREMENTS_LIST 
	11 REG_QWORD			64-bits int (uint64_t) 
	11 REG_QWORD_LITTLE_ENDIAN 
*/
  int j;
  switch(dwtype)
  { 
    case 1: {//REG_SZ 
	char str[dwLen];
	addr2str(lpData, dwLen, (char*)str);
	WRITE("tracehooklog", "type=REG_SZ\ndata=%s\n", str);
	break;
    }
    case 2: {//REG_EXPAND_SZ
	char val[dwLen];
	for(j=0;j<dwLen;j++) val[j]='\0';
	read_mem(lpData, dwLen, (unsigned char*)val);  
	WRITE("tracehooklog", "type=REG_EXPAND_SZ\ndata=%s\n", val);
	break;
    } 
    case 3: {//REG_BINARY
	WRITE("tracehooklog", "type=REG_BINARY\ndata=");			
	unsigned char val[dwLen];
	for(j=0;j<dwLen;j++) val[j]='\0';	
	read_mem(lpData, dwLen, (unsigned char*)&val); 	
	for (j=0;j<dwLen;j++) WRITE("tracehooklog", "%02X", val[j]);		WRITE("tracehooklog", "\n");
	break;
    }	
    case 4: {//REG_DWORD 
	unsigned long val = 0;
	read_mem(lpData, sizeof(val), (unsigned char*)&val); 
	WRITE("tracehooklog", "type=REG_DWORD\ndata=%d\n", val);
	break; 
    }
    case 7: {//REG_MULTI_SZ
	WRITE("tracehooklog", "type=REG_MULTI_SZ\ndata=");		
	char val[dwLen];
	for(j=0;j<dwLen;j++) val[j]='\0';
	read_mem(lpData, dwLen, (unsigned char*)val);  
	for (j=0; j<dwLen; j++)
	{
	  if(val[j]=='\0') WRITE("tracehooklog", " ");
	  if(val[j]!='\0') WRITE("tracehooklog", "%c", val[j]);
	}
	WRITE("tracehooklog", "\n");
	break;
    }
    default: break;
  }  
}

uint32_t print_procInfo(uint32_t pInfo)
{
  uint32_t buf[4];
  read_mem(pInfo, sizeof(buf), (unsigned char*)buf);
/*
	typedef struct _PROCESS_INFORMATION {
	0  HANDLE hProcess;
	1  HANDLE hThread;
	2  DWORD  dwProcessId;
	3  DWORD  dwThreadId;
	} PROCESS_INFORMATION, *LPPROCESS_INFORMATION;
*/
  WRITE("tracehooklog", "dwProcessId=%d\ndwThreadId=%d\n", buf[2], buf[3]);

  return buf[2];
}

 // Li : we dont determine whether this API is success or failure at this moment, we will write a parser to do that.
int print_Eax(succeed_t succeed)
{
  uint32_t eax = 0;
  read_reg(eax_reg, &eax);
  WRITE("tracehooklog", "Return=%lx\n",eax);//just record eax value
  return 0;
  // if(succeed == NONZERO)
  // {
  //   if(eax != 0)
  //   {
  //     WRITE("tracehooklog", "Return=SUCCESS\n");
  //     return 1; //MIKE: how about return eax?
  //   }
  //   else
  //   {
  //     WRITE("tracehooklog", "Return=FAILURE\n");	
  //     return 0;
  //   }
  // }
  // else if(succeed == HANDLE)
  // {
  //   if(eax == 0)
  //   {
  //     WRITE("tracehooklog", "Return=FAILURE\n");
  //     return 0;
  //   }
  //   else
  //   {
  //     WRITE("tracehooklog", "Return=SUCCESS\n");
  //     return eax;
  //   }
  // }
  // else if(succeed == REG)
  // {
  //   if(eax == 0)
  //   {
  //     WRITE("tracehooklog", "Return=SUCCESS\n");
  //     return 1;
  //   }
  //   else
  //   {
  //     WRITE("tracehooklog", "result=FAILURE\n");
  //     return 0;
  //   }
  // }
  // else return -1; // should not be here
}

void print_procAccess(uint32_t access)
{
  //MIKE: too heaavy, sprintf is better

  WRITE("tracehooklog", "desiredAccess=");	
  if(access & 0x00010000) WRITE("tracehooklog", "DELETE ");
  if(access & 0x00020000) WRITE("tracehooklog", "READ_CONTROL ");
  if(access & 0x00100000) WRITE("tracehooklog", "SYNCHRONIZE ");	
  if(access & 0x00040000) WRITE("tracehooklog", "WRITE_DAC ");
  if(access & 0x00080000) WRITE("tracehooklog", "WRITE_OWNER ");
  
  if(access & 0x0080) WRITE("tracehooklog", "PROCESS_CREATE_PROCESS ");
  if(access & 0x0002) WRITE("tracehooklog", "PROCESS_CREATE_THREAD ");
  if(access & 0x0040) WRITE("tracehooklog", "PROCESS_DUP_HANDLE ");
  if(access & 0x0400) WRITE("tracehooklog", "PROCESS_QUERY_INFORMATION ");
  if(access & 0x1000) WRITE("tracehooklog", "PROCESS_QUERY_LIMITED_INFORMATION ");
  if(access & 0x0200) WRITE("tracehooklog", "PROCESS_SET_INFORMATION ");
  if(access & 0x0100) WRITE("tracehooklog", "PROCESS_SET_QUOTA ");
  if(access & 0x0800) WRITE("tracehooklog", "PROCESS_SUSPEND_RESUME ");
  if(access & 0x0001) WRITE("tracehooklog", "PROCESS_TERMINATE ");
  if(access & 0x0008) WRITE("tracehooklog", "PROCESS_VM_OPERATION ");
  if(access & 0x0010) WRITE("tracehooklog", "PROCESS_VM_READ ");
  if(access & 0x0020) WRITE("tracehooklog", "PROCESS_VM_WRITE ");
  WRITE("tracehooklog", "\n");
}

void print_fileAccess(uint32_t access)
{
  WRITE("tracehooklog", "desiredAccess=");
  if(access & 0x10000000) WRITE("tracehooklog", "GENERIC_ALL ");
  if(access & 0x80000000) WRITE("tracehooklog", "GENERIC_READ ");
  if(access & 0x40000000) WRITE("tracehooklog", "GENERIC_WRITE ");
  if(access & 0x20000000) WRITE("tracehooklog", "GENERIC_EXECUTE ");
  WRITE("tracehooklog", "\n");
}

void print_fileDisposition(uint32_t disposition)
{
  WRITE("tracehooklog", "creationDisposition=");
  switch(disposition)
  {
    case 2:
      WRITE("tracehooklog", "CREATE_ALWAYS\n");
      break;
    case 1:
      WRITE("tracehooklog", "CREATE_NEW\n");
      break;
    case 4:  
      WRITE("tracehooklog", "OPEN_ALWAYS\n");
      break;
    case 3:  
      WRITE("tracehooklog", "OPEN_EXISTING\n");
      break;	
     case 5: 
      WRITE("tracehooklog", "TRUNCATE_EXISTING\n");
      break;	
     default:
      WRITE("tracehooklog", "unknown\n");
      break;
  }
}


//======== LoadLibrary ==========
int LoadLibrary_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	HMODULE WINAPI LoadLibrary(
  	1  __in  LPCTSTR lpFileName
	);
  */

  /* Store parameters so that they can be used by return hook */
  loadlibrary_t *s = (loadlibrary_t*)calloc(1,sizeof(loadlibrary_t));
  if (s == NULL) return 0;

  s->lpFileName = buf[1];

  s->hook_handle = hookapi_hook_return(buf[0], LoadLibrary_ret, s, sizeof(loadlibrary_t));
  s->tick = clock();

  return 0;
}

int LoadLibrary_ret(void *opaque)
{
  loadlibrary_t *s = (loadlibrary_t *)opaque;

  char str[256]="";
  addr2str(s->lpFileName, 256, (char*)str);
  WRITE("tracehooklog", "#%ld\nLoadLibrary\nlpFileName=%s\n", s->tick, str);
  print_Eax(NONZERO);

  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//======== CopyFile ==========
int CopyFile_call(void *opaque)
{
  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	BOOL WINAPI CopyFile(
	1  _In_  LPCTSTR lpExistingFileName,
	2  _In_  LPCTSTR lpNewFileName,
	   _In_  BOOL bFailIfExists
	);
	BOOL WINAPI CopyFileEx(
	1  __in      LPCTSTR lpExistingFileName,
	2  __in      LPCTSTR lpNewFileName,
	  __in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
	  __in_opt  LPVOID lpData,
	  __in_opt  LPBOOL pbCancel,
	  __in      DWORD dwCopyFlags
	);
  */

  /* Store parameters so that they can be used by return hook */
  copyfile_t *s = (copyfile_t*)calloc(1,sizeof(copyfile_t));
  if (s == NULL) return 0;

  s->lpExistingFileName = buf[1];
  s->lpNewFileName = buf[2];
 
  s->hook_handle = hookapi_hook_return(buf[0], CopyFile_ret, s, sizeof(copyfile_t));
  s->tick = clock();

  return 0;
}

int CopyFile_ret(void *opaque)
{
  if(!is_tracing)
  {
    fprintf(stdout, "CopyFile_ret assert, tracepid: %d\n", tracepid);
    return 0; // MIKE: I add it back, but not necessory. No need to monitor other process now. Go to see should_monitor.
  }

  copyfile_t *s = (copyfile_t *)opaque;

  char str1[256]="";
  addr2str(s->lpExistingFileName, 256, (char*)str1);
  char str2[256]="";
  addr2str(s->lpNewFileName, 256, (char*)str2);

  if(!is_tracing) //MIKE: this return is called before next basic block, but the current process (even the current block) is not the original traced process
  {
   //MIKE: no need to load/match them in my version.
   // match_bot_file((string)str1);
   // match_bot_file((string)str2);
   ;
  }  
  
  if(is_tracing) // MIke: note _bot_() might change is_tracing
  {
    WRITE("tracehooklog", "#%ld\nCopyFile\nlpExistingFileName=%s\n", s->tick, str1);	
    WRITE("tracehooklog", "lpNewFileName=%s\n", str2);
    print_Eax(NONZERO);
  }

  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//======== CreateFile ==========
int CreateFile_call(void *opaque)
{
  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	HANDLE WINAPI CreateFile(
	1  __in      LPCTSTR lpFileName,  // full path
	2  __in      DWORD dwDesiredAccess, //read, write, both
	3  __in      DWORD dwShareMode, 
	4  __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	5  __in      DWORD dwCreationDisposition, //Cre
	6  __in      DWORD dwFlagsAndAttributes,
	7  __in_opt  HANDLE hTemplateFile
	);
  */

  /* Store parameters so that they can be used by return hook */
  createfile_t *s = (createfile_t*)calloc(1,sizeof(createfile_t));
  if (s == NULL) return 0;

  s->hName = buf[1];
  s->DesiredAccess = buf[2];
  s->ShareMode = buf[3];
  s->CreationDisposition = buf[5];

  s->hook_handle = hookapi_hook_return(buf[0], CreateFile_ret, s, sizeof(createfile_t));
  s->tick = clock();

  return 0;
}

int CreateFile_ret(void *opaque)
{
  if(!is_tracing)
  {
    fprintf(stdout, "CreateFile_ret assert, tracepid: %d\n", tracepid);
    return 0;
  }

  createfile_t *s = (createfile_t *)opaque;

  char str[256]="";
  addr2str(s->hName, 256, (char*)str);

  if(!is_tracing)
  {
    //match_bot_file((string)str);
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    if(eax != 0xFFFFFFFF) // 0xFFFFFFFF is INVALID_HANDLE_VALUE
    {
      add_proc_handle(eax, (string)str);
    }
  }

  if(is_tracing) // MIKE: note _bot_() might change is_tracing
  {
    WRITE("tracehooklog", "#%ld\nCreateFile\nhName=%s\n", s->tick, str); 
    print_fileAccess(s->DesiredAccess);
    print_fileDisposition(s->CreationDisposition);
    
    /* Check return value -> status */
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    WRITE("tracehooklog", "Return=%lx\n",eax); 
 //    if(eax != 0xFFFFFFFF)
 //    {
	// WRITE("tracehooklog", "Return=SUCCESS\n");
	// add_proc_handle(eax, (string)str);
 //    }
 //    else
 //    {
	// WRITE("tracehooklog", "Return=FAILURE\n");
 //    }
  }
  
  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//======== WriteFile ==========
int WriteFile_call(void *opaque)
{
  //MIKE: writefile need a handle as input, which means the process already open or create a file before. Since we do not want to print out every write call. We simply discard such hook;
  return 0;

  if(!is_tracing) return 0;
 
  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	BOOL WINAPI WriteFileEx(
	1  __in      HANDLE hFile,
	2  __in_opt  LPCVOID lpBuffer,
	3  __in      DWORD nNumberOfBytesToWrite,
	4  __inout   LPOVERLAPPED lpOverlapped,
	5  __in_opt  LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	);
  */

  rwdfile_t *s = (rwdfile_t*)calloc(1,sizeof(rwdfile_t));
  if (s == NULL) return 0;

  s->hFile = buf[1];

  s->hook_handle = hookapi_hook_return(buf[0], WriteFile_ret, s, sizeof(rwdfile_t));
  s->tick = clock();

  return 0; 
}

int WriteFile_ret(void *opaque)
{
  if(!is_tracing) return 0;
  
  rwdfile_t *s = (rwdfile_t *)opaque;
 
  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);
  
  string fileName;
  find_proc_handle(s->hFile, &fileName);
  WRITE("tracehooklog", "#%ld\nWriteFile\nfileName=%s\n", s->tick, fileName.c_str());
  print_Eax(NONZERO); // for WriteFile, return nonzero = succeed

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//======== ReadFile ==========
int ReadFile_call(void *opaque)
{
  //MIKE: see WriteFile_call
  return 0;

  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	BOOL WINAPI ReadFile(
	  __in         HANDLE hFile,
	  __out        LPVOID lpBuffer,
	  __in         DWORD nNumberOfBytesToRead,
	  __out_opt    LPDWORD lpNumberOfBytesRead,
	  __inout_opt  LPOVERLAPPED lpOverlapped
	);
  */

  rwdfile_t *s = (rwdfile_t*)calloc(1,sizeof(rwdfile_t));
  if (s == NULL) return 0;

  s->hFile = buf[1];

  s->hook_handle = hookapi_hook_return(buf[0], ReadFile_ret, s, sizeof(rwdfile_t));
  s->tick = clock();

  return 0; 
}

int ReadFile_ret(void *opaque)
{
  if(!is_tracing) return 0;

  rwdfile_t *s = (rwdfile_t *)opaque;
  
  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  string fileName;
  find_proc_handle(s->hFile, &fileName);
  WRITE("tracehooklog", "#ld\nReadFile\nfileName=%s\n", s->tick, fileName.c_str());
  print_Eax(NONZERO);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//======== DeleteFile ==========
int DeleteFile_call(void *opaque)
{
  if(!is_tracing) return 0;
  //MIKE: DeleteFile need no handle -> assert, no need to check is_tracing.

  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*	
	BOOL WINAPI DeleteFile(
	  __in  LPCTSTR lpFileName
	);
  */

  rwdfile_t *s = (rwdfile_t*)calloc(1,sizeof(rwdfile_t));
  if (s == NULL) return 0;

  s->hFile = buf[1];

  s->hook_handle = hookapi_hook_return(buf[0], DeleteFile_ret, s, sizeof(rwdfile_t));
  s->tick = clock();

  return 0; 
}

int DeleteFile_ret(void *opaque)
{
  if(!is_tracing) return 0;

  rwdfile_t *s = (rwdfile_t *)opaque;

  char str[256]="";
  addr2str(s->hFile, 256, (char*)str); // see _call, hFile is actually lpFileName

  if(!is_tracing)
  {
    //match_bot_file((string)str);
    ;
  }

  if(is_tracing) //MIKE: note _bot_() might change is_tracing
  {
    WRITE("tracehooklog", "#%ld\nDeleteFile\nfileName=%s\n", s->tick, str);
    print_Eax(NONZERO);
  }
  
  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}








//======== CreateProcess  ==========

int CreateProcess_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[11]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
      	BOOL WINAPI CreateProcess(
	1  __in_opt     LPCTSTR lpApplicationName,
	2  __inout_opt  LPTSTR lpCommandLine,
	3  __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
	4  __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
	5  __in         BOOL bInheritHandles,
	6  __in         DWORD dwCreationFlags,  ->!
	7  __in_opt     LPVOID lpEnvironment,
	8  __in_opt     LPCTSTR lpCurrentDirectory,
	9  __in         LPSTARTUPINFO lpStartupInfo,
	10 __out        LPPROCESS_INFORMATION lpProcessInformation
	);
  */

  /* Store parameters so that they can be used by return hook */
  createprocess_t *s = (createprocess_t*)calloc(1,sizeof(createprocess_t));
  if (s == NULL) return 0;

  s->lpApplicationName = buf[1];
  s->lpCommandLine = buf[2];
  s->lpProcessInformation= buf[10];
 
  s->hook_handle = hookapi_hook_return(buf[0], CreateProcess_ret, s, sizeof(createprocess_t));
  s->tick = clock();

  return 0;
}

int CreateProcess_ret(void *opaque)
{
  if(!is_tracing) return 0;

  createprocess_t *s = (createprocess_t *)opaque;

  WRITE("tracehooklog", "#%ld\nCreateProcess\n", s->tick); 
 
  if(s->lpApplicationName!=0)
  {
    char str1[256]="";
    addr2str(s->lpApplicationName, 256, (char*)str1);
    WRITE("tracehooklog", "lpApplicationName=%s\n", str1);
  }
  if(s->lpCommandLine!=0)
  {
    char str2[256]="";
    addr2str(s->lpCommandLine, 256, (char*)str2);
    WRITE("tracehooklog", "lpCommandLine=%s\n", str2);	
  }
  if(print_Eax(NONZERO))
  {
    uint32_t pid;	
    pid = print_procInfo(s->lpProcessInformation);
    tracing_start(pid, "CreateProcess_ret");//MIKE: the 2nd arg can be lpApplicationName or lpCommandLine
  }

  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//======== CreateProcessInternal ==========
int CreateProcessInternal_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[12]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
      	BOOL WINAPI CreateProcessInternalW(
	1  __in         BOOL bFlags;
	2  __in_opt     LPCTSTR lpApplicationName,
	3  __inout_opt  LPTSTR lpCommandLine,
	4  __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
	5  __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
	6  __in         BOOL bInheritHandles,
	7  __in         DWORD dwCreationFlags,
	8  __in_opt     LPVOID lpEnvironment,
	9  __in_opt     LPCTSTR lpCurrentDirectory,
	10  __in        LPSTARTUPINFO lpStartupInfo,
	11  __out       LPPROCESS_INFORMATION lpProcessInformation
	);
  */

  /* Store parameters so that they can be used by return hook */
  createprocess_t *s = (createprocess_t*)calloc(1,sizeof(createprocess_t));
  if (s == NULL) return 0;

  s->lpApplicationName = buf[2];
  s->lpCommandLine=buf[3];
  s->lpProcessInformation= buf[11];
  
  s->hook_handle = hookapi_hook_return(buf[0], CreateProcessInternal_ret, s, sizeof(createprocess_t));
  s->tick = clock();

  return 0;
}

int CreateProcessInternal_ret(void *opaque)
{
  if(!is_tracing) return 0;

  createprocess_t *s = (createprocess_t *)opaque;

  WRITE("tracehooklog", "#%ld\nCreateProcessInternal\n", s->tick); // this func is the same as CreateProcess_ret, except this line

  if(s->lpApplicationName!=0)
  {
    char str1[256]="";
    addr2str(s->lpApplicationName, 256, (char*)str1);
    WRITE("tracehooklog", "lpApplicationName=%s\n", str1);
  }
  if(s->lpCommandLine!=0)
  {
    char str2[256]="";
    addr2str(s->lpCommandLine, 256, (char*)str2);
    WRITE("tracehooklog", "lpCommandLine=%s\n", str2);
  }
  if(print_Eax(NONZERO))
  {
    uint32_t pid;
    pid = print_procInfo(s->lpProcessInformation);
    tracing_start(pid, "CreateProcess_ret");//MIKE: the 2nd arg can be lpApplicationName or lpCommandLine
  }

  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//======== OpenProcess ==========
int OpenProcess_call(void *opaque)
{
  if(!is_tracing) return 0; //MIKE: if no check, every process can enter here?

  uint32_t cr3 = 0;
  read_reg(cr3_reg, &cr3);
  fprintf(stdout,"in open process call, cr3=%d\n", cr3);
  uint32_t esp;
  uint32_t buf[5]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	HANDLE WINAPI OpenProcess(
	1  __in  DWORD dwDesiredAccess,
	2  __in  BOOL bInheritHandle,
	3  __in  DWORD dwProcessId
	);
  */

  /* Store parameters so that they can be used by return hook */
  openprocess_t *s = (openprocess_t*)calloc(1,sizeof(openprocess_t));
  if (s == NULL) return 0;

  s->dwDesiredAccess = buf[1];
  s->dwProcessId= buf[3];
 
  s->hook_handle = hookapi_hook_return(buf[0], OpenProcess_ret, s, sizeof(openprocess_t));
  s->tick = clock();

  return 0;
}

int OpenProcess_ret(void *opaque)
{
  if(!is_tracing) return 0; //MIKE: if commented, non-traced process might be here? see OpenProcess_call

  openprocess_t *s = (openprocess_t *)opaque;

  uint32_t eax = 0;
  read_reg(eax_reg, &eax);
  if(eax != 0) // ==0 fail
  {
    char proc_name[32] = "";
    find_procname(s->dwProcessId, (char*) proc_name);
    add_proc_handle(s->dwProcessId, (string)proc_name);
  }

  if(is_tracing)
  {
    WRITE("tracehooklog", "#%ld\nOpenProcess\n", s->tick);
    print_procAccess(s->dwDesiredAccess);
    WRITE("tracehooklog", "dwProcessId=%d\n", s->dwProcessId);

    int handle = print_Eax(HANDLE);
    if(handle)
    {
      char proc_name[32] = "";
      find_procname(s->dwProcessId, (char*) proc_name);
      WRITE("tracehooklog", "procName=%s\n", proc_name);
      add_proc_handle(handle, (string)proc_name);
      //tracing_start(s->dwProcessId); //MIKE:?
    }
  }

  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//======== ExitProcess ==========
int ExitProcess_call(void *opaque)
{
  /*
	This function does not return a value.
  */

  if(is_tracing)
  {
    WRITE("tracehooklog", "#%ld\nExitProcess\n", clock());
  }

  return 0;
}

//======== TerminateProcess ==========
int TerminateProcess_call(void *opaque)
{
  /*
  This function does not return a value.
  */

  if(is_tracing)
  {
    WRITE("tracehooklog", "#%ld\nTerminateProcess\n", clock());
  }

  return 0;
}

//======== WinExec ==========
int WinExec_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[5]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	UINT WINAPI WinExec(
	 1 __in  LPCSTR lpCmdLine,
	   __in  UINT uCmdShow
	);
  */
  /* Store parameters so that they can be used by return hook */
  winexec_t *s = (winexec_t*)calloc(1,sizeof(winexec_t));
  if (s == NULL) return 0;

  s->lpCmdLine = buf[1];
  s->tick = clock();
 
  s->hook_handle = hookapi_hook_return(buf[0], WinExec_ret, s, sizeof(winexec_t));

  return 0;
}

int WinExec_ret(void *opaque)
{
  if(!is_tracing) return 0;

  winexec_t *s = (winexec_t *)opaque;
  
  char str[512]="";
  addr2str(s->lpCmdLine, 512, (char*)str);
  WRITE("tracehooklog", "#%ld\nWinExec\nlpCmdLine=%s\n", s->tick, str);
  print_Eax(NONZERO);
 
  

  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//======== CreateRemoteThread ==========
int CreateRemoteThread_call(void *opaque)
{
  if(!is_tracing) return 0; //MIKE: handle is an __in !! hook all proc? but I don't think so.

  uint32_t esp;
  uint32_t buf[5]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	HANDLE WINAPI CreateRemoteThread(
	1  __in   HANDLE hProcess,
	  __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
	  __in   SIZE_T dwStackSize,
	  __in   LPTHREAD_START_ROUTINE lpStartAddress,
	  __in   LPVOID lpParameter,
	  __in   DWORD dwCreationFlags,
	7  __out  LPDWORD lpThreadId
	);
  */
  /* Store parameters so that they can be used by return hook */
  createremotethread_t *s = (createremotethread_t*)calloc(1,sizeof(createremotethread_t));
  if (s == NULL) return 0;

  s->hProcess = buf[1];
 
  s->hook_handle = hookapi_hook_return(buf[0], CreateRemoteThread_ret, s, sizeof(createremotethread_t));
  s->tick = clock();

  return 0;
}

int CreateRemoteThread_ret(void *opaque)
{
  if(!is_tracing) return 0;

  createremotethread_t *s = (createremotethread_t *)opaque;
  
  if(is_tracing)
  {
    string proc_name;
    if(find_proc_handle(s->hProcess, &proc_name))
    {
      WRITE("tracehooklog", "#%ld\nCreateRemoteThread\nprocName=%s\n", s->tick, proc_name.c_str());
      print_Eax(HANDLE);
      const char* proc = proc_name.c_str();
      int pid = find_pid_by_name(proc);
      if(pid > 0)
      {
        WRITE("tracehooklog", "pId=%d\n", pid);
	 tracing_start(pid, proc);
      }
    }
  }

  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//======== OpenThread ==========
int OpenThread_call(void *opaque)
{
  if(!is_tracing) return 0; 

  uint32_t esp;
  uint32_t buf[5]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
  HANDLE WINAPI OpenThread(
1  _In_ DWORD dwDesiredAccess,
2  _In_ BOOL  bInheritHandle,
3  _In_ DWORD dwThreadId
);
  */

  /* Store parameters so that they can be used by return hook */
  openthread_t *s = (openthread_t*)calloc(1,sizeof(openthread_t));
  if (s == NULL) return 0;

  s->dwThreadId = buf[3];
  s->hook_handle = hookapi_hook_return(buf[0], OpenThread_ret, s, sizeof(openthread_t));
  s->tick = clock();

  return 0;
}

int OpenThread_ret(void *opaque)
{
  if(!is_tracing) return 0;

  openthread_t *s = (openthread_t *)opaque;
  
  if(is_tracing)
  {
      WRITE("tracehooklog", "#%ld\nOpenThread\ndwThreadId=%d\n", s->tick, s->dwThreadId);
      print_Eax(HANDLE);   
  }

  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//======== CreateThread ==========
int CreateThread_call(void *opaque)
{
  if(!is_tracing) return 0; 

  uint32_t esp;
  uint32_t buf[7]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

/*
HANDLE WINAPI CreateThread(
1  _In_opt_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
2  _In_      SIZE_T                 dwStackSize,
3  _In_      LPTHREAD_START_ROUTINE lpStartAddress,
4  _In_opt_  LPVOID                 lpParameter,
5  _In_      DWORD                  dwCreationFlags,
6  _Out_opt_ LPDWORD                lpThreadId
);
*/

  /* Store parameters so that they can be used by return hook */
  openthread_t *s = (openthread_t*)calloc(1,sizeof(openthread_t));
  if (s == NULL) return 0;

  s->dwThreadId = buf[6];
  s->hook_handle = hookapi_hook_return(buf[0], CreateThread_ret, s, sizeof(openthread_t));
  s->tick = clock();

  return 0;
}

int CreateThread_ret(void *opaque)
{
  if(!is_tracing) return 0;

  openthread_t *s = (openthread_t *)opaque;
  
  if(is_tracing)
  {
      WRITE("tracehooklog", "#%ld\nCreateThread\ndwThreadId=%d\n", s->tick, s->dwThreadId);
      print_Eax(HANDLE);   
  }

  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//======== TerminateThread ==========
int TerminateThread_call(void *opaque)
{
  if(!is_tracing) return 0; 

  uint32_t esp;
  uint32_t buf[3]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

/*
BOOL WINAPI TerminateThread(
1  _Inout_ HANDLE hThread,
2  _In_    DWORD  dwExitCode
);
*/

  /* Store parameters so that they can be used by return hook */
  terminatethread_t *s = (terminatethread_t*)calloc(1,sizeof(terminatethread_t));
  if (s == NULL) return 0;
  s->hThread = buf[1];
  s->hook_handle  = hookapi_hook_return(buf[0], TerminateThread_ret, s, sizeof(terminatethread_t));
  s->tick = clock();

  return 0;
}

int TerminateThread_ret(void *opaque)
{
  if(!is_tracing) return 0;

  terminatethread_t *s = (terminatethread_t *)opaque;
  
  if(is_tracing)
  {
      uint32_t eax = 0;
      read_reg(eax_reg, &eax);
      WRITE("tracehooklog", "#%ld\nTerminateThread\nhThread=%lx\nReturn=%lx\n", s->tick , s->hThread, eax);
   }

  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//======== CloseHandle ==========
int CloseHandle_call(void *opaque)
{
  if(!is_tracing) return 0; // no is_tracing here, MIKE: why? I use should_monitor before!

  uint32_t esp;
  uint32_t buf[2]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	BOOL WINAPI CloseHandle(
	1  __in  HANDLE hObject
	);
  */

  /* Store parameters so that they can be used by return hook */
  closehandle_t *s = (closehandle_t*)calloc(1,sizeof(closehandle_t));
  if (s == NULL) return 0;

  s->hObject = buf[1];

  s->hook_handle = hookapi_hook_return(buf[0], CloseHandle_ret, s, sizeof(closehandle_t));
  s->tick = clock();

  return 0;
}

int CloseHandle_ret(void *opaque)
{
  closehandle_t *s = (closehandle_t *)opaque;

#if 0
  if(is_tracing)
  {
    WRITE("tracehooklog", "#%ld\n=CloseHandle\nhObject=%x\n", s->tick, s->hObject);
    //MIKE: can print info of this handle and eax here, but not implemented.
  }
#endif

  rmv_proc_handle(s->hObject);

  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);

  return 0;
}

//============= RegOpenCurrentUser =============
int RegOpenCurrentUser_call(void *opaque)
{
  uint32_t esp;
  
  uint32_t buf[3]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	LONG WINAPI RegOpenCurrentUser(
	  __in   REGSAM samDesired,
	2  __out  PhKey phkresult
	);
  */

  /* Store parameters so that they can be used by return hook */
  regopenkey_t *s = (regopenkey_t*)calloc(1,sizeof(regopenkey_t));
  if (s == NULL) return 0;

  s->phkresult = buf[2];
  
  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], RegOpenCurrentUser_ret, s, sizeof(regopenkey_t));
  s->tick = clock();

  return 0;
}

int RegOpenCurrentUser_ret(void *opaque)
{  
  if(!is_tracing) return 0;

  regopenkey_t *s = (regopenkey_t *)opaque;
   
   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);
  
  /* Check return value -> status */

  uint32_t eax = 0;
  read_reg(eax_reg, &eax);
  if(eax == 0) // succeed
  {
    uint32_t bf2;
    read_mem(s->phkresult, sizeof(bf2), (unsigned char*)&bf2);
    add_proc_handle(bf2, "HKEY_CURRENT_USER");
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//============= RegOpenKey =============
int RegOpenKeyEx_call(void *opaque)
{
  uint32_t esp;
  
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	LONG WINAPI RegOpenKeyEx(
	1  __in        hKey hKey,
	2  __in_opt    LPCTSTR lpSubKey,
	3  __reserved  DWORD ulOptions,
	4  __in        REGSAM samDesired,
	5  __out       PhKey phkresult
  */

  /* Store parameters so that they can be used by return hook */
  regopenkey_t *s = (regopenkey_t*)calloc(1,sizeof(regopenkey_t));
  if (s == NULL) return 0;

  s->hKey = buf[1];
  s->lpSubKey = buf[2];
  s->phkresult = buf[5];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], RegOpenKeyEx_ret, s, sizeof(regopenkey_t));
  return 0;
}

int RegOpenKeyEx_ret(void *opaque)
{
  if(!is_tracing) return 0;

  regopenkey_t *s = (regopenkey_t *)opaque;
   
   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);
  
  /* Check return value -> status */

  char key[256]="";
  hkey2str(s->hKey, key);
  string hKey = (string)key;

  if(s->lpSubKey!=0)
  {
    char str[256]="";
    addr2str(s->lpSubKey, 256, (char*)str);
    hKey = hKey + "\\" +(string)str;		
  }

  uint32_t eax = 0;
  read_reg(eax_reg, &eax);
  if(eax == 0) // succeed
  {
    uint32_t bf2;
    read_mem(s->phkresult, sizeof(bf2), (unsigned char*)&bf2);
    add_proc_handle(bf2, hKey);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ RegQueryValueEx ================
int RegQueryValueEx_call(void *opaque)
{
  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	LONG WINAPI RegQueryValueEx(
	1  __in         hKey hKey,
	2  __in_opt     LPCTSTR lpValueName,
	   __reserved   LPDWORD lpReserved,
	4  __out_opt    LPDWORD lpType,
	5  __out_opt    LPBYTE lpData,
	6  __inout_opt  LPDWORD lpcbData
	);

  */

  /* Store parameters so that they can be used by return hook */
  regqueryvalue_t *s = (regqueryvalue_t*)calloc(1,sizeof(regqueryvalue_t));
  if (s == NULL) return 0;

  s->hKey = buf[1];
  s->lpValueName = buf[2];
  s->lpType = buf[4];
  s->lpData = buf[5];
  s->lpcbData = buf[6];
 
  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], RegQueryValueEx_ret, s, sizeof(regqueryvalue_t));
  s->tick = clock();

  return 0;
}

int RegQueryValueEx_ret(void *opaque)
{
  if(!is_tracing) return 0; //MIKE: I dont need tainted any registery in my version.

  regqueryvalue_t *s = (regqueryvalue_t *)opaque;
  
   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char key[256]="";
  hkey2str(s->hKey, (char*)key); 
  string hKey = (string)key;

  if(s->lpValueName!=0)
  {
    char str[128]="";
    addr2str(s->lpValueName, 128, (char*)str); 
    hKey = hKey + "\\" +(string)str;	
  }

  if(!is_tracing)
  {
    //match_bot_reg(hKey);
    ;
  }

  if(is_tracing)
  {
    WRITE("tracehooklog", "#%ld\nRegQueryValue\nhKey=%s\n", s->tick, hKey.c_str());
    if(print_Eax(REG))
    {
      unsigned long cbData;
      unsigned long dwType;

      if(s->lpType!=0) read_mem(s->lpType, sizeof(dwType), (unsigned char*)&dwType);
      if(s->lpcbData!=0) read_mem(s->lpcbData, sizeof(cbData), (unsigned char*)&cbData); 
      if(s->lpType!=0 && s->lpcbData!=0 && s->lpcbData!=0)
      {
        print_regData(dwType, cbData, s->lpData);
      }
    }
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ RegEnumValue ================
int RegEnumValue_call(void *opaque)
{
  uint32_t esp;
  uint32_t buf[9]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	LONG WINAPI RegEnumValue(
	1  __in         hKey hKey,
	2  __in         DWORD dwIndex,
	3  __out        LPTSTR lpValueName,
	4  __inout      LPDWORD lpcchValueName,
	5  __reserved   LPDWORD lpReserved,
	6  __out_opt    LPDWORD lpType,
	7  __out_opt    LPBYTE lpData,
	8  __inout_opt  LPDWORD lpcbData
	);
  */
  /* Store parameters so that they can be used by return hook */
  regqueryvalue_t *s = (regqueryvalue_t*)calloc(1,sizeof(regqueryvalue_t));
  if (s == NULL) return 0;

  s->hKey = buf[1];
  s->lpValueName = buf[3];
  s->lpcchValueName = buf[4];
  s->lpType = buf[6];
  s->lpData = buf[7];
  s->lpcbData = buf[8];
 
  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], RegEnumValue_ret, s, sizeof(regqueryvalue_t));
  s->tick = clock();

  return 0;
}

int RegEnumValue_ret(void *opaque)
{
  if(!is_tracing) return 0;

  regqueryvalue_t *s = (regqueryvalue_t *)opaque;
  
   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char key[256]="";
  hkey2str(s->hKey, key); 
  string hKey = (string)key;

  uint32_t eax = 0;
  read_reg(eax_reg, &eax);
  if(eax == 0) /// succeed
  {
    unsigned long cchValueName;
    read_mem(s->lpcchValueName, sizeof(cchValueName), (unsigned char*)&cchValueName);         

    char str[256]="";	
    addr2str(s->lpValueName, cchValueName, (char*)str);
    hKey = hKey + "\\" +(string)str;
	
    if(!is_tracing)
    {
      //match_bot_reg(hKey);
      ;
    }

    if(is_tracing)
    {
      WRITE("tracehooklog", "#%ld\nRegEnumValue\nhKey=%s\n", s->tick, hKey.c_str());
      print_Eax(REG);

      unsigned long cbData;
      unsigned long dwType;
      if(s->lpType!=0) read_mem(s->lpType, sizeof(dwType), (unsigned char*)&dwType); 
      if(s->lpcbData!=0) read_mem(s->lpcbData, sizeof(cbData), (unsigned char*)&cbData); 
      if(s->lpType!=0 && s->lpcbData!=0 && s->lpcbData!=0)
      {
        print_regData(dwType, cbData, s->lpData);
      }
    }
  }	  

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ RegCloseKey ================
int RegCloseKey_call(void *opaque)
{
  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  regsetvalue_t *s = (regsetvalue_t*)calloc(1,sizeof(regsetvalue_t));
  if (s == NULL) return 0;
  /*
	LONG WINAPI RegCloseKey(
	1  __in  hKey hKey
	);
  */
  s->hKey=buf[1];
  
/* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], RegCloseKey_ret, s, sizeof(regopenkey_t));
  s->tick = clock();

  return 0;
}

int RegCloseKey_ret(void *opaque)
{
  if(!is_tracing) return 0;

  regsetvalue_t *s = (regsetvalue_t *)opaque;
  
   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  //MIKE: no need to do so.

  rmv_proc_handle(s->hKey);
	 
  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ RegSetValue ================
int RegSetValue_call(void *opaque)
{
  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	LONG WINAPI RegSetValue(
	1  __in      hKey hKey,
	2  __in_opt  LPCTSTR lpSubKey,
	3  __in      DWORD dwType,
	4  __in      LPCTSTR lpData,
	5  __in      DWORD cbData
	);
  */
  /* Store parameters so that they can be used by return hook */
  regsetvalue_t *s = (regsetvalue_t*)calloc(1,sizeof(regsetvalue_t));
  if (s == NULL) return 0;

  s->hKey = buf[1];
  s->lpSubKey = buf[2];
  s->dwType = buf[3];
  s->lpData = buf[4];
  s->cbData = buf[5];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], RegSetValue_ret, s, sizeof(regsetvalue_t));
  s->tick = clock();

  return 0;
}

int RegSetValue_ret(void *opaque)
{
  if(!is_tracing) return 0;

  regsetvalue_t *s = (regsetvalue_t *)opaque;
  
  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);
  
  /* Read stack starting at ESP */
  char key[256]="";
  hkey2str(s->hKey, key);
  string hKey = (string)key;

  if(s->lpSubKey!=0)
  {
    char str[256]="";  
    addr2str(s->lpSubKey, 256, (char*)str);
    hKey = hKey + "\\" +(string)str; 
  }

  if(!is_tracing)
  {
    //match_bot_reg(hKey);
    ;
  }

  if(is_tracing)
  {
    WRITE("tracehooklog", "#%ld\nRegSetValue\nhKey=%s\n", s->tick, hKey.c_str());	
    print_regData(s->dwType, s->cbData, s->lpData);
    print_Eax(REG);
  }
   	 
  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ RegSetValueEx ================
int RegSetValueEx_call(void *opaque)
{
  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	LONG WINAPI RegSetValueEx(
	1  __in      hKey hKey,
	2  __in_opt  LPCTSTR lpSubKey,
        3  _Reserved_  DWORD Reserved,
	4  __in      DWORD dwType,
	5  __in      LPCTSTR lpData,
	6  __in      DWORD cbData
	);
  */
  /* Store parameters so that they can be used by return hook */
  regsetvalue_t *s = (regsetvalue_t*)calloc(1,sizeof(regsetvalue_t));
  if (s == NULL) return 0;

  s->hKey = buf[1];
  s->lpSubKey = buf[2];
  s->dwType = buf[4];
  s->lpData = buf[5];
  s->cbData = buf[6];
 
  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], RegSetValueEx_ret, s, sizeof(regsetvalue_t));
  s->tick = clock();

  return 0;
}

int RegSetValueEx_ret(void *opaque)
{
  if(!is_tracing) return 0;

  regsetvalue_t *s = (regsetvalue_t *)opaque;
  
   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);
  
  /* Read stack starting at ESP */
  char key[256]="";
  hkey2str(s->hKey, key);
  string hKey = (string)key;

  if(s->lpSubKey!=0)
  {
    char str[256]="";  
    addr2str(s->lpSubKey, 256, (char*)str);
    hKey = hKey + "\\" +(string)str; 
  }

  if(!is_tracing)
  {
    //match_bot_reg(hKey);
    ;
  }

  if(is_tracing)
  {
    WRITE("tracehooklog", "#%ld\nRegSetValue\nhKey=%s\n", s->tick, hKey.c_str());
    print_regData(s->dwType, s->cbData, s->lpData);
    print_Eax(REG);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ RegCreateKey ================
int RegCreateKey_call(void *opaque)
{
  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	LONG WINAPI RegCreateKey(
	1  __in      hKey hKey,
	2  __in_opt  LPCTSTR lpSubKey,
	3  __out     PhKey phkresult
	);
  */

  /* Store parameters so that they can be used by return hook */
  regopenkey_t *s = (regopenkey_t*)calloc(1,sizeof(regopenkey_t));
  if (s == NULL) return 0;

  s->hKey = buf[1];
  s->lpSubKey = buf[2];
  s->phkresult = buf[3];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], RegCreateKey_ret, s, sizeof(regopenkey_t));
  s->tick = clock();

  return 0;
}

int RegCreateKey_ret(void *opaque)
{
  if(!is_tracing) return 0;

  regopenkey_t *s = (regopenkey_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */ 
  char key[256]="";
  hkey2str(s->hKey, key);
  string hKey = (string)key;

  if(s->lpSubKey!=0)
  {
    char str[256]="";  
    addr2str(s->lpSubKey, 256, (char*)str);
    hKey = hKey + "\\" +(string)str;
  }

  if(!is_tracing)
  {
    //match_bot_reg(hKey); 

    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    if(eax == 0) //succeed
    {
      uint32_t bf2;
      read_mem(s->phkresult, sizeof(bf2), (unsigned char*)&bf2);
      add_proc_handle(bf2, hKey);
    }
  }

  if(is_tracing)
  {
    WRITE("tracehooklog", "#%ld\nRegCreateKey\nhKey=%s\n", s->tick, hKey.c_str());
    if(print_Eax(REG))
    {
      uint32_t bf2;
      read_mem(s->phkresult, sizeof(bf2), (unsigned char*)&bf2);
      add_proc_handle(bf2, hKey);
    }
  }
  
  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ RegCreateKeyEx ================
int RegCreateKeyEx_call(void *opaque)
{
  uint32_t esp;
  uint32_t buf[10]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	LONG WINAPI RegCreateKeyEx(
	1  __in        hKey hKey,
	2  __in        LPCTSTR lpSubKey,
	3  __reserved  DWORD Reserved,
	4  __in_opt    LPTSTR lpClass,
	5  __in        DWORD dwOptions,
	6  __in        REGSAM samDesired,
	7  __in_opt    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	8  __out       PhKey phkresult,
	9  __out_opt   LPDWORD lpdwDisposition
	);
  */

  /* Store parameters so that they can be used by return hook */
  regopenkey_t *s = (regopenkey_t*)calloc(1,sizeof(regopenkey_t));
  if (s == NULL) return 0;

  s->hKey = buf[1];
  s->lpSubKey = buf[2];
  s->phkresult = buf[8];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], RegCreateKey_ret, s, sizeof(regopenkey_t));
  s->tick = clock();

  return 0;
}

//================ RegDeleteKey RegDeleteKeyEx ================
int RegDeleteKey_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
	LONG WINAPI RegDeleteKey(
	1  __in  hKey hKey,
	2  __in  LPCTSTR lpSubKey
	);

 	LONG WINAPI RegDeleteKeyEx(
	1  __in        hKey hKey,
	2  __in        LPCTSTR lpSubKey,
	3  __in        REGSAM samDesired,
	4  __reserved  DWORD Reserved
	);
  */

  /* Store parameters so that they can be used by return hook */
  regopenkey_t *s = (regopenkey_t*)calloc(1,sizeof(regopenkey_t));
  if (s == NULL) return 0;

  s->hKey = buf[1];
  s->lpSubKey = buf[2];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], RegDeleteKey_ret, s, sizeof(regopenkey_t));
  s->tick = clock();

  return 0;
}

int RegDeleteKey_ret(void *opaque)
{
  if(!is_tracing) return 0;

  regopenkey_t *s = (regopenkey_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char key[256]="";
  hkey2str(s->hKey, key);
  string hKey = (string)key;

  char str[256]="";
  addr2str(s->lpSubKey, 256, (char*)str);
  hKey = hKey + "\\" +(string)str;

  if(!is_tracing)
  {
    //match_bot_reg(hKey);
    ;
  }
 
  if(is_tracing)
  {
    WRITE("tracehooklog", "#%ld\nRegDeleteKey\nhKey=%s\n", s->tick, hKey.c_str());
    print_Eax(REG);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ WinHttpConnect ================
int WinHttpConnect_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[5]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
HINTERNET WINAPI WinHttpConnect(
1  _In_       HINTERNET     hSession,
2  _In_       LPCWSTR       pswzServerName, //we only retrieve this arg
3  _In_       INTERNET_PORT nServerPort,
4  _Reserved_ DWORD         dwReserved
);
  */

  /* Store parameters so that they can be used by return hook */
  winhttpconnect_t *s = (winhttpconnect_t*)calloc(1,sizeof(winhttpconnect_t));
  if (s == NULL) return 0;

  s->url = buf[2];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], WinHttpConnect_ret, s, sizeof(winhttpconnect_t));
  s->tick = clock();

  return 0;
}

int WinHttpConnect_ret(void *opaque)
{
  if(!is_tracing) return 0;

  winhttpconnect_t *s = (winhttpconnect_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char server[256]="";
  addr2str(s->url, 256, (char*)server);
  string pswzservername = (string)server;

  if(is_tracing)
  {
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    WRITE("tracehooklog", "#%ld\nWinHttpConnect\npswzServerName=%s\nReturn=%lx\n", s->tick, pswzservername.c_str(),eax );
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ WinHttpCreateUrl================
int WinHttpCreateUrl_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[5]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
BOOL WINAPI WinHttpCreateUrl(
1  _In_    LPURL_COMPONENTS lpUrlComponents,
2  _In_    DWORD            dwFlags,
3  _Out_   LPWSTR           pwszUrl, //we only retrieve this arg
4  _Inout_ LPDWORD          lpdwUrlLength
);
  */

  /* Store parameters so that they can be used by return hook */
  winhttpconnect_t *s = (winhttpconnect_t*)calloc(1,sizeof(winhttpconnect_t));
  if (s == NULL) return 0;

  s->url = buf[3];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], WinHttpCreateUrl_ret, s, sizeof(winhttpconnect_t));
  s->tick = clock();

  return 0;
}

int WinHttpCreateUrl_ret(void *opaque)
{
  if(!is_tracing) return 0;

  winhttpconnect_t *s = (winhttpconnect_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char tmpurl[256]="";
  addr2str(s->url, 256, (char*)tmpurl);
  string npwszUrl = (string)tmpurl;

  if(is_tracing)
  {
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    WRITE("tracehooklog", "#%ld\nWinHttpCreateUrl\npwszUrl=%s\nReturn=%lx\n", s->tick, npwszUrl.c_str(), eax);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ WinHttpOpen================
int WinHttpOpen_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[6]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
HINTERNET WINAPI WinHttpOpen(
1  _In_opt_ LPCWSTR pwszUserAgent, //we only retrieve this arg
2  _In_     DWORD   dwAccessType,
3  _In_     LPCWSTR pwszProxyName,
4  _In_     LPCWSTR pwszProxyBypass,
5  _In_     DWORD   dwFlags
);
  */

  /* Store parameters so that they can be used by return hook */
  winhttpconnect_t *s = (winhttpconnect_t*)calloc(1,sizeof(winhttpconnect_t));
  if (s == NULL) return 0;

  s->url = buf[1];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], WinHttpOpen_ret, s, sizeof(winhttpconnect_t));
  s->tick = clock();

  return 0;
}

int WinHttpOpen_ret(void *opaque)
{
  if(!is_tracing) return 0;

  winhttpconnect_t *s = (winhttpconnect_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char tmpurl[256]="";
  addr2str(s->url, 256, (char*)tmpurl);
  string pwszUserAgent = (string)tmpurl;

  if(is_tracing)
  {
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    WRITE("tracehooklog", "#%ld\nWinHttpOpen\npwszUserAgent=%s\nReturn=%lx\n", s->tick, pwszUserAgent.c_str(), eax);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ WinHttpOpenRequest================
int WinHttpOpenRequest_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
HINTERNET WINAPI WinHttpOpenRequest(
1_In_ HINTERNET hConnect,
2_In_ LPCWSTR   pwszVerb,
3_In_ LPCWSTR   pwszObjectName, //we only retrieve this arg
4_In_ LPCWSTR   pwszVersion,
5  _In_ LPCWSTR   pwszReferrer,
6  _In_ LPCWSTR   *ppwszAcceptTypes,
7  _In_ DWORD     dwFlags
);
  */

  /* Store parameters so that they can be used by return hook */
  winhttpconnect_t *s = (winhttpconnect_t*)calloc(1,sizeof(winhttpconnect_t));
  if (s == NULL) return 0;

  s->url = buf[3];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], WinHttpOpenRequest_ret, s, sizeof(winhttpconnect_t));
  s->tick = clock();

  return 0;
}

int WinHttpOpenRequest_ret(void *opaque)
{
  if(!is_tracing) return 0;

  winhttpconnect_t *s = (winhttpconnect_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char tmpurl[256]="";
  addr2str(s->url, 256, (char*)tmpurl);
  string pwszObjectName = (string)tmpurl;

  if(is_tracing)
  {
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    WRITE("tracehooklog", "#%ld\nWinHttpOpenRequest\npwszObjectName=%s\nReturn=%lx\n", s->tick, pwszObjectName.c_str(), eax);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ WinHttpReadData================
int WinHttpReadData_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[5]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
BOOL WINAPI WinHttpReadData(
  1_In_  HINTERNET hRequest,
  2_Out_ LPVOID    lpBuffer, //we only retrieve this arg
  3_In_  DWORD     dwNumberOfBytesToRead,
  4_Out_ LPDWORD   lpdwNumberOfBytesRead
);
  */

  /* Store parameters so that they can be used by return hook */
  winhttpconnect_t *s = (winhttpconnect_t*)calloc(1,sizeof(winhttpconnect_t));
  if (s == NULL) return 0;

  s->url = buf[2];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], WinHttpReadData_ret, s, sizeof(winhttpconnect_t));
  s->tick = clock();

  return 0;
}

int WinHttpReadData_ret(void *opaque)
{
  if(!is_tracing) return 0;

  winhttpconnect_t *s = (winhttpconnect_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char tmp_str[256]="";
  addr2str(s->url, 256, (char*)tmp_str);
  string lpBuffer = (string)tmp_str;

  if(is_tracing)
  {
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    WRITE("tracehooklog", "#%ld\nWinHttpReadData\nlpBuffer=%s\nReturn=%lx\n", s->tick, lpBuffer.c_str(), eax);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ WinHttpSendRequest================
int WinHttpSendRequest_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[8]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
BOOL WINAPI WinHttpSendRequest(
  1_In_     HINTERNET hRequest,
  2_In_opt_ LPCWSTR   pwszHeaders,  //we only retrieve this arg
  3_In_     DWORD     dwHeadersLength,
  4_In_opt_ LPVOID    lpOptional,
  5_In_     DWORD     dwOptionalLength,
  6_In_     DWORD     dwTotalLength,
  7_In_     DWORD_PTR dwContext
);
  */

  /* Store parameters so that they can be used by return hook */
  winhttpconnect_t *s = (winhttpconnect_t*)calloc(1,sizeof(winhttpconnect_t));
  if (s == NULL) return 0;

  s->url = buf[2];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], WinHttpSendRequest_ret, s, sizeof(winhttpconnect_t));
  s->tick = clock();

  return 0;
}

int WinHttpSendRequest_ret(void *opaque)
{
  if(!is_tracing) return 0;

  winhttpconnect_t *s = (winhttpconnect_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char tmp_str[256]="";
  addr2str(s->url, 256, (char*)tmp_str);
  string pwszHeaders = (string)tmp_str;

  if(is_tracing)
  {
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    WRITE("tracehooklog", "#%ld\nWinHttpSendRequest\npwszHeaders=%s\nReturn=%lx\n", s->tick, pwszHeaders.c_str(), eax);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ WinHttpWriteData================
int WinHttpWriteData_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[5]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
BOOL WINAPI WinHttpWriteData(
 1 _In_  HINTERNET hRequest,
 2 _In_  LPCVOID   lpBuffer, //we only retrieve this arg
 3 _In_  DWORD     dwNumberOfBytesToWrite,
 4_Out_ LPDWORD   lpdwNumberOfBytesWritten
);
  */

  /* Store parameters so that they can be used by return hook */
  winhttpconnect_t *s = (winhttpconnect_t*)calloc(1,sizeof(winhttpconnect_t));
  if (s == NULL) return 0;

  s->url = buf[2];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], WinHttpWriteData_ret, s, sizeof(winhttpconnect_t));
  s->tick = clock();

  return 0;
}

int WinHttpWriteData_ret(void *opaque)
{
  if(!is_tracing) return 0;

  winhttpconnect_t *s = (winhttpconnect_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char tmp_str[256]="";
  addr2str(s->url, 256, (char*)tmp_str);
  string lpBuffer = (string)tmp_str;

  if(is_tracing)
  {
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    WRITE("tracehooklog", "#%ld\nWinHttpWriteData\nlpBuffer=%s\nReturn=%lx\n", s->tick, lpBuffer.c_str(), eax);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ WinHttpGetProxyForUrl================
int WinHttpGetProxyForUrl_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[5]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
BOOL WINAPI WinHttpGetProxyForUrl(
  1_In_  HINTERNET                 hSession,
  2_In_  LPCWSTR                   lpcwszUrl, //we only retrieve this arg
  3_In_  WINHTTP_AUTOPROXY_OPTIONS *pAutoProxyOptions,
  4_Out_ WINHTTP_PROXY_INFO        *pProxyInfo
);
  */

  /* Store parameters so that they can be used by return hook */
  winhttpconnect_t *s = (winhttpconnect_t*)calloc(1,sizeof(winhttpconnect_t));
  if (s == NULL) return 0;

  s->url = buf[2];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], WinHttpGetProxyForUrl_ret, s, sizeof(winhttpconnect_t));
  s->tick = clock();

  return 0;
}

int WinHttpGetProxyForUrl_ret(void *opaque)
{
  if(!is_tracing) return 0;

  winhttpconnect_t *s = (winhttpconnect_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char tmp_str[256]="";
  addr2str(s->url, 256, (char*)tmp_str);
  string lpcwszUrl = (string)tmp_str;

  if(is_tracing)
  {
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    WRITE("tracehooklog", "#%ld\nWinHttpGetProxyForUrl\nlpcwszUrl=%s\nReturn=%lx\n", s->tick, lpcwszUrl.c_str(), eax);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ InternetOpen================
int InternetOpen_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[6]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
HINTERNET InternetOpen(
  1_In_ LPCTSTR lpszAgent,  //we only retrieve this argument
  2_In_ DWORD   dwAccessType,
  3_In_ LPCTSTR lpszProxyName,
  4_In_ LPCTSTR lpszProxyBypass,
  5_In_ DWORD   dwFlags
);
  */

  /* Store parameters so that they can be used by return hook */
  winhttpconnect_t *s = (winhttpconnect_t*)calloc(1,sizeof(winhttpconnect_t));
  if (s == NULL) return 0;

  s->url = buf[1];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], InternetOpen_ret, s, sizeof(winhttpconnect_t));
  s->tick = clock();

  return 0;
}

int InternetOpen_ret(void *opaque)
{
  if(!is_tracing) return 0;

  winhttpconnect_t *s = (winhttpconnect_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char tmp_str[256]="";
  addr2str(s->url, 256, (char*)tmp_str);
  string lpszAgent = (string) tmp_str;

  if(is_tracing)
  {
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    WRITE("tracehooklog", "#%ld\nInternetOpen\nlpszAgent=%s\nReturn=%lx\n", s->tick, lpszAgent.c_str(), eax);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ InternetConnect================
int InternetConnect_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[9]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
HINTERNET InternetConnect(
  1_In_ HINTERNET     hInternet,
  2_In_ LPCTSTR       lpszServerName, //we only retrieve this argument
  3_In_ INTERNET_PORT nServerPort,
  4_In_ LPCTSTR       lpszUsername,
  5_In_ LPCTSTR       lpszPassword,
  6_In_ DWORD         dwService,
  7_In_ DWORD         dwFlags,
  8_In_ DWORD_PTR     dwContext
);
 */

  /* Store parameters so that they can be used by return hook */
  winhttpconnect_t *s = (winhttpconnect_t*)calloc(1,sizeof(winhttpconnect_t));
  if (s == NULL) return 0;

  s->url = buf[2];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], InternetConnect_ret, s, sizeof(winhttpconnect_t));
  s->tick = clock();

  return 0;
}

int InternetConnect_ret(void *opaque)
{
  if(!is_tracing) return 0;

  winhttpconnect_t *s = (winhttpconnect_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char tmp_str[256]="";
  addr2str(s->url, 256, (char*)tmp_str);
  string lpszServerName = (string) tmp_str;

  if(is_tracing)
  {
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    WRITE("tracehooklog", "#%ld\nInternetConnect\nlpszServerName=%s\nReturn=%lx\n", s->tick, lpszServerName.c_str(), eax);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ HttpSendRequest================
int HttpSendRequest_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[6]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
BOOL HttpSendRequest(
  1_In_ HINTERNET hRequest,
  2_In_ LPCTSTR   lpszHeaders, //we only retrieve this arg
  3_In_ DWORD     dwHeadersLength,
  4_In_ LPVOID    lpOptional,
  5_In_ DWORD     dwOptionalLength
);
 */

  /* Store parameters so that they can be used by return hook */
  winhttpconnect_t *s = (winhttpconnect_t*)calloc(1,sizeof(winhttpconnect_t));
  if (s == NULL) return 0;

  s->url = buf[2];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], HttpSendRequest_ret, s, sizeof(winhttpconnect_t));
  s->tick = clock();

  return 0;
}

int HttpSendRequest_ret(void *opaque)
{
  if(!is_tracing) return 0;

  winhttpconnect_t *s = (winhttpconnect_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char tmp_str[256]="";
  addr2str(s->url, 256, (char*)tmp_str);
  string lpszHeaders = (string) tmp_str;

  if(is_tracing)
  {
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    WRITE("tracehooklog", "#%ld\nHttpSendRequest\nlpszHeaders=%s\nReturn=%lx\n", s->tick, lpszHeaders.c_str(), eax);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}

//================ GetUrlCacheEntryInfo================
int GetUrlCacheEntryInfo_call(void *opaque)
{
  if(!is_tracing) return 0;

  uint32_t esp;
  uint32_t buf[4]; // Assumes that all stack parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /*
BOOL GetUrlCacheEntryInfo(
  1_In_    LPCTSTR                     lpszUrlName, //we only retrieve this arg
  2_Out_   LPINTERNET_CACHE_ENTRY_INFO lpCacheEntryInfo,
  3_Inout_ LPDWORD                     lpcbCacheEntryInfo
);
 */

  /* Store parameters so that they can be used by return hook */
  winhttpconnect_t *s = (winhttpconnect_t*)calloc(1,sizeof(winhttpconnect_t));
  if (s == NULL) return 0;

  s->url = buf[1];

  /* Hook return of function */
  s->hook_handle = hookapi_hook_return(buf[0], GetUrlCacheEntryInfo_ret, s, sizeof(winhttpconnect_t));
  s->tick = clock();

  return 0;
}

int GetUrlCacheEntryInfo_ret(void *opaque)
{
  if(!is_tracing) return 0;

  winhttpconnect_t *s = (winhttpconnect_t *)opaque;

   /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  char tmp_str[256]="";
  addr2str(s->url, 256, (char*)tmp_str);
  string lpszUrlName = (string) tmp_str;

  if(is_tracing)
  {
    uint32_t eax = 0;
    read_reg(eax_reg, &eax);
    WRITE("tracehooklog", "#%ld\nGetUrlCacheEntryInfo\nlpszUrlName=%s\nReturn=%lx\n", s->tick, lpszUrlName.c_str(), eax);
  }

  /* Free structure used to pass info between call and return hooks */
  if (s) free(s);
  
  return 0;
}