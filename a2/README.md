# CSC 361 - Assignment 2
### TCP Traffic Analysis Documentation

##### Author: AJ Po-Deziel
##### Date created: 2018-02-15

## Dependencies
- Python 3.6 or higher
- dpkt 1.9.1

## How to compile and run
1. Open Terminal (macOS) or Command Prompt/PowerShell (Windows).

2. Navigate to folder containing zipped submission folder.

3. Unzip submission folder. Once done, navigate to unzipped folder.

4. Install the necessary dependencies. If Python 3.6 or higher is already installed, you may install **dpkt** with pip.
    ```
    pip install dpkt
    ```

5. Execute the TCP Traffic Analysis program with the following command.
    ```
    python tcp_trace_analysis.py [capture_file]
    ```
    
    Where **[capture_file]** is the name of the packet capture file to be analyzed.
    
## Notes
* When printing out **Start time** and **End time** to console, the date & time of packet capture is printed out, 
not the time from when the packet capture began (i.e. in seconds)

* If multiple reset flags are encountered in the same connection, as per the assignment spec, they are not counted.
Instead, a boolean flag (True/False) is utilized to determine if a connection has ever been reset. If it is, this flag
is set to **True**, with no possibility of changing it back to **False**.