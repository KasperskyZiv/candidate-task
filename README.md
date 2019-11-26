
# SAMR 

## MSRPC using Python
This is a tool uses MSRPC protocol (Microsoft implementation of DCERPC) in order to manage a remote Windows
 machine. 
You can find any information regarding the MS-SAMR API interface used in the following [link](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380).

It was written as a part of a [home assigment](/task/README.md) for Cymptom.

Current features:
1. Create\Delete a local user\group\alias
2. Retrieve all users\groups\alias

This code can be easily extended for more functionality. 
This also demonstrate in my opinion some concept of OOP, with incorporation of tests, python Dataclass,
and a nice decorator use case.


### Requirements
- You should be using `Python > 3.8`
- `pip install -r requirements.txt`


