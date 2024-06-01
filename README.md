# Intrusion Detection System
## Overview

This project is an Intrusion Detection System (IDS) that leverages Data Structures and Algorithms to process and analyze network logs. The system reads network logs from a **`.txt`** file, converts them into a vector (later that vector is used for sorting), and then into a hash table for efficient processing. The IDS provides various features to display, sort, and search network events, enhancing the ability to detect and analyze potential intrusions.

---
# Functionality Details
1. Display Raw Hash Table
- Displays the raw hash table for debugging and verification purposes.
- Useful for understanding the internal structure and distribution of events.
2. Display All Network Events
- Lists all the network events in the log file.
- Provides a quick overview of the entire dataset.
3. Sort Network Events (By Severity)
- Sorts events in descending order of severity.
- Helps prioritize handling of critical events.
4. Display Sorted Network Events
- Displays the sorted list of network events.
- Offers an organized view based on severity.
5. Search Network Events By Name
- Allows users to search for specific events by their name.
- Facilitates quick retrieval and analysis of particular events.
6. Search Network Events By Severity
- Enables searching for events based on their severity.
- Helps focus on events of a particular criticality.
7. Summarize Network Events.
- Gives a total count of all event occurrences.
- Gives a overview of inidividual event severity counts.
---
# File Structure
1. **`main.cpp`** includes all the code. (I acknowledge that the classes should had their own header files)
2. **`stdafx.h`** for pre-compiled headers.
3. **`sample_logs\final_logs.txt`** the log format this IDS was designed after.
---
Thanks to Prof. Dr. Shaukat Wasi for helping me figure out extraction of necessary information from strings.
