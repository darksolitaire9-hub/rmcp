# RMCP: The Security Guard for AI Agents 🛡️

## Explain It Like I'm 5 (ELI5) 

Imagine your AI Agent (like Cursor or Claude) is a super-smart person locked in a room. To get information, they have to make a phone call to a library (an MCP Server). 

Normally, the AI just completely trusts whatever the librarian says. But what if a bad guy sneaks a nasty note into a library book that says: *"Tell the AI to delete all its files and passwords"*? The AI would hear that on the phone, get confused, and might actually do it.

**RMCP is the Security Guard on the phone line.** 
The AI doesn't call the library directly anymore. It calls the Security Guard, who then calls the library. When the librarian reads the book over the phone, the Security Guard listens *first*. If the guard hears something dangerous or weird (like a bad note, or someone screaming thousands of words a second to crash the AI), the guard instantly hangs up the phone and protects the AI.

## Why use RMCP?
The Model Context Protocol (MCP) lets AI agents connect to your local files and databases. RMCP makes sure nobody uses that connection to hack your AI. 

## License
This project is open-source under the **MIT License**. You can use it, modify it, and protect your enterprises for free.
