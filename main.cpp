#include <iostream>
#include <list>
#include <algorithm>
#include <string>
#include <cctype>
#include <unordered_map> 
#include <ctime>
using namespace std;

string eventSevereLevel(string s) {
	//Built in Hash Table
	unordered_map<string, string> umap;
	umap["failed_login_attempts"] = "Moderate";
	umap["application_access_denied"] = "Moderate";
	umap["port_scan"] = "Severe";
	umap["suspicious_extension"] = "Moderate";
	umap["blacklisted_IP_address"] = "Severe";
	umap["unusual_activity"] = "Severe";
	umap["unauthorized_IP_address"] = "Severe";
	umap["unusual termination for active user"] = "Extremely Severe";
	umap["log integrity check failed"] = "Extremely Severe";
	umap["DoS_attack"] = "Critical";
}

class logData {
public:
	string eventName, eventSeverity, hostIP, protocol;
	time_t eventTime;
	int source_port;
	int destination_port;
	logData(string eN, string hIP) {
		eventName = eN;
		eventSeverity = eventSevereLevel(eventName);
		hostIP = hIP;
	}
};

class hashTable {
	list<logData>* hash;
	int size;
public:
	hashTable() {
		size = 10;
		hash = new list<logData>[size];
	}

	const int chars = 256; //Number of chars in input
	const int p = 11; //any prime number
	int hashFunction(logData l) {
		int bucket = 0;
		int len = l.eventName.length();
		for (int i = 0; i < len; i++) {
			bucket = ( bucket * chars + tolower(l.eventName[i]) ) % p;
		}
		return (bucket + p) % p;
	}

	logData filterLog(string s) {

	}

	void insert(string log) {
		
	}
};

int main() {
	logData l("Failed Login", "10.0.0.1"), l1("Failed Login", "192.168.1.11");
	hashTable h;
	cout << h.hashFunction(l) << endl;
	cout << h.hashFunction(l1) << endl;
}