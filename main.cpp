#include <iostream>
#include <list> //hashTable
#include <algorithm> //hashTable insertion
#include <string>
#include <cctype> //tolower
#include <unordered_map> 
#include <ctime>
#include <sstream> //parsetime func
#include <iomanip> //parsetime func
#include <fstream>
#include <vector>
#include <regex> //pattern Matching
using namespace std;

string eventSevereLevel(string s) {
	//Built in Hash Table
	unordered_map<string, string> umap;
	umap["Authentication failure"] = "Moderate";
	umap["Access denied"] = "Moderate";
	umap["Network intrusion detected"] = "Severe";
	umap["Suspicious activity"] = "Moderate";
	umap["Security alert"] = "Severe";
	umap["Anomalous behavior"] = "Severe";
	umap["Unauthorized access attempt"] = "Moderate";
	umap["Security breach"] = "Extremely Severe";
	umap["Denial of Service (DoS) attack detected"] = "Critical";
	umap["Login failure"] = "Moderate";
	umap["ERROR"] = "Low";
	umap["DEBUG"] = "None";
	umap["INFO"] = "None";
	umap["WARNING"] = "None";

	return umap[s];
}

void extractIPAdd(string s, string& sIP, string& dIP) {
	regex pattern(R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)");
	smatch match;

	while (regex_search(s, match, pattern)) {
		sIP = match[0];
		s = match.suffix().str();  // Update string to ignore preceding elements
		if (regex_search(s, match, pattern)) {
			dIP = match[0];
		}
		break;
	}
}

//string extractEventName(string s) {
//	size_t colonPos = s.find(":"); //returns index
//	if (colonPos != string::npos) { //index isn't invalid
//		string res = s.substr(0, colonPos);
//		if (res != "ERROR" && res != "WARNING" && res != "INFO" && res != "DEBUG") return res;
//	}
//	return "";
//}

time_t parseTime(string& timestamp) {
	std::tm tm = { 0 };  // Initialize tm structure to zero
	std::istringstream ss(timestamp);
	ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");  // Parse the string into tm structure

	if (ss.fail()) {
		throw runtime_error("Failed to parse time");
	}

	return mktime(&tm);  // Convert tm structure to time_t
}

string formatTime(time_t time) {
	char buffer[26];
	ctime_s(buffer, sizeof(buffer), &time);
	return string(buffer);
}

string extractEventName(string s, time_t& time) {
	// Combine timestamp and event name patterns
	regex timestamp_pattern(R"((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}))");
	smatch match;

	if (regex_search(s, match, timestamp_pattern)) {
		string t = match[1].str();
		time = parseTime(t);
		s = s.substr(match.position() + match.length()); // String after timestamp
	}

	size_t colonPos = s.find(":");
	if (colonPos != string::npos) {
		// Find the first non-timestamp character before the colon
		size_t startPos = s.find_first_not_of("0123456789:- ", 0);
		if (startPos < colonPos) {
			return s.substr(startPos, colonPos - startPos); // Extract event name excluding timestamp
		}
	}
	return "";
}

void extractEventProtocol(string s, string& protocol, string& sourcePort, string& destPort) {
	regex pattern(R"((TCP|UDP)\s+(\d+(-\d+)?)\s+(\d+(-\d+)?))");
	smatch match;

	if (regex_search(s, match, pattern)) {
		protocol = match[1].str();                
		sourcePort = match[2].str();        
		destPort = match[4].str(); 
	}
	else {
		protocol = "";
		sourcePort = "";
		destPort = "";
	}
}

class logData {
public:
	string eventName, eventSeverity, protocol;
	time_t eventTime;
	string source_port;
	string destination_port;
	string sourceIP;
	string destIP;
	logData(string log) {
		eventName = extractEventName(log, eventTime);
		if (eventName == "") return; //avoid calling functions
		eventSeverity = eventSevereLevel(eventName);
		extractIPAdd(log, sourceIP, destIP);
		extractEventProtocol(log, protocol, source_port, destination_port);
	}

	void display() {
		cout << "Timestamp = " << formatTime(eventTime); // ctime function does \n on its own
		cout << "Event Name = " << eventName << endl;
		cout << "Event Severity = " << eventSeverity << endl;
		cout << "Source IP = " << sourceIP << endl;
		cout << "Destination IP = " << destIP << endl;
		cout << "Protocol = " << protocol << endl;
		cout << "Source Port = " << source_port << endl;
		cout << "Destination Port = " << destination_port << endl << endl;
	}
};

class hashTable {
	list<logData>* hash;
	int size;
public:
	hashTable() {
		size = 14;
		hash = new list<logData>[size];
	}

	~hashTable() {
		delete hash;
	}

	const int chars = 256; //Number of chars in input
	const int p = 15; //any prime number
	int hashFunction(logData l) {
		int bucket = 0;
		int len = l.eventName.length();
		for (int i = 0; i < len; i++) {
			bucket = ( bucket * chars + tolower(l.eventName[i]) ) % p;
		}
		return (bucket + p) % p;
	}

	void insert(logData log) {
		int idx = hashFunction(log);
		hash[idx].push_back(log);
	}

	void display() {
		for (int i = 0; i < size; i++) {
			cout << i << ": ";
			for (auto it = hash[i].begin(); it != hash[i].end(); it++) {
				cout << it->eventName << ", ";
			}
			cout << endl;
		}
	}
};

vector<logData> readLogs() {
	string line;
	string path;
	vector<logData> logs;

	cout << "Enter path to read logs from (including file name): ";
	cin >> path;

	ifstream file(path);
	if (!file.is_open()) {
		throw runtime_error("Failed to open file.");
	}
	while (getline(file, line)) {
		logData l(line);
		logs.push_back(l);
	}

	file.close();
	return logs;
}

void displayVecLogs(vector<logData>& log) {
	for (int i = 0; i < log.size(); i++) {
		log[i].display();
	}
}

hashTable vecToHTable(vector<logData>& v) {
	hashTable h;
	for (int i = 0; i < v.size(); i++) {
		h.insert(v[i]);
	}
	return h;
}

int main() {
	logData l("2024-05-16 02:31:00 INFO: System update installed. Version: 2.1.0 127.0.0.1 127.0.0.1 TCP 22 54321");
	l.display();
	/*hashTable h;
	cout << h.hashFunction(l) << endl;
	cout << h.hashFunction(l1) << endl;*/

	vector<logData> logs = readLogs();
	//displayVecLogs(logs);
	//hashTable h = vecToHTable(logs);
	hashTable h;
	h.insert(l);
	h.display();
	//h.display();
}