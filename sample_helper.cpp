#include <sstream>
#include <stdio.h>
#include <string>
#include <iconv.h>
#include <iostream>
#include <fstream>
#include <map>
#include <stdint.h>
#include <vector>
#include "tracecap/tracecap.h"
using namespace std;
vector<string> bot_file = vector<string>();
vector<string> bot_reg = vector<string>();


/* for API handle mapping */
map<uint32_t, map<int, string>*> proc_handle_map;
map<int,string>::iterator handle_it;
map<uint32_t, map<int, string>*>::iterator proc_handle_it;

string itos(int i){
		
  stringstream ss;
  string str;
  ss << hex << i;
  ss >> str;
  return str;	
}

int find_proc_handle(int handle, string* output){
  proc_handle_it = proc_handle_map.find(tracecr3);

  //if proc does not have a handle map, create it
  if(proc_handle_it == proc_handle_map.end()){
	proc_handle_map[tracecr3]= new map<int,string> ;
	*output	= itos(handle);
	return 0;
  }
  else {//if the map is created
 	map<int,string> *inner_map = NULL;
	inner_map = proc_handle_it->second;
	handle_it = inner_map->find(handle);

	if(handle_it == inner_map->end()){
		*output	= itos(handle);		
		return 0;
	}
	else{		
		*output = handle_it->second;	
		return 1;
	}
  }
}

void add_proc_handle(int handle, string input){

  proc_handle_it = proc_handle_map.find(tracecr3);

  //if proc does not have a handle map, create it
  if(proc_handle_it == proc_handle_map.end()){
	map<int,string>* inner_map = new map<int,string>;	
	proc_handle_map[tracecr3]= inner_map;
	(*inner_map)[handle]=input;
  }
  else {//if the map is created
	map<int,string> *inner_map2 = NULL;
	inner_map2 = proc_handle_it->second;
	(*inner_map2)[handle]=input;
  }
}

void rmv_proc_handle(int handle){
  proc_handle_it = proc_handle_map.find(tracecr3);

  //if proc does not have a handle map, create it
  if(proc_handle_it == proc_handle_map.end()){
	proc_handle_map[tracecr3]= new map<int,string> ;
  }
  else {//if the map is created
 	map<int,string> *inner_map = NULL;
	inner_map = proc_handle_it->second;
	handle_it = inner_map->find(handle);

	if(handle_it == inner_map->end()){
	}
	else{		
		inner_map->erase(handle);
	}
  }
}
#if 0
void load_bot_profile(){

  ifstream regFile;
  regFile.open("bot_profile/bot_reg.txt");//"Virut_2.hooklog"
  string output;

  while (!regFile.eof()){
	getline(regFile,output);
	if(output!="")	bot_reg.push_back(output);	
  }
  regFile.close();

  ifstream fileFile;
  fileFile.open("bot_profile/bot_file.txt");//"Virut_2.hooklog"
  while (!fileFile.eof()){
	getline(fileFile,output);	
	if(output!="")	bot_file.push_back(output);	
  }
  regFile.close();
  cout<< "Load bot profile from:\nbot_profile/bot_reg.txt\nbot_profile/bot_file.txt\n";
}

int match_bot_reg(string input){

  for(int i=0; i<(int)bot_reg.size(); i++)
	if(bot_reg[i].compare(input)==0){
		cout<<"find bot reg activity: "<<input<<endl;
		*is_tracing = 1;
		cout<<"start to monitor: "<< tracepid<<endl;
		return 1;
	}
  return 0;
}

int match_bot_file(string input){

  for(int i=0; i<(int)bot_file.size(); i++)
	if(bot_file[i].compare(input)==0){
		cout<<"find bot reg activity: "<<input<<endl;
		*is_tracing = 1;
		cout<<"start to monitor: "<< tracepid<<endl;
		return 1;
	}
  return 0;
}

#endif
