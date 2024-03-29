# University of Victoria
### CSC 361: Assignment 1 - Smart Web Client Documentation

###### Author: AJ Po-Deziel
###### Created on: 2018-01-23


## File List
* **smart_client.py**: Web client that collects information on a web server. Implementation of Assignment 1 is contained entirely within this file.


## Dependencies
There are no external dependencies required to run smart_client.

For smart_client to compile and run, Python 3.6 or higher is required.


## How to run smart_client.py
1.  You've most likely unzipped the file! Huzzah!
2.  Ensure that Python 3.6 or higher is installed on your machine.
3.  Open Terminal on UNIX-based OS, or Command Prompt or PowerShell
    on Windows OS.
4.  Navigate to the directory where you have unzipped the .zip file.
5.  Execute the following command on the command line:

    ```
    python smart_client.py [web address]
    ```

    Where **[web address]** is a web address inputted by the user. The
    web address must be of the following format, as shown in the
    examples below:

    * www.google.ca
    * www.uvic.ca
    * www.aircanada.com

    **PLEASE NOTE THE FOLLOWING ABOUT USER INPUT!!**
    
    ->  There is no need to include the "http://" prefix. 
        Doing so will cause the program to reject your input.

    ->  Inputting an invalid web address, or one not registered
        will result in the program rejecting your input.

    ->  If no web address is inputted, the program will raise an
        exception, and will terminate/exit.
    
    ->  If more than 1 web address is inputted, the program will
        raise an exception, and will terminate/exit.
