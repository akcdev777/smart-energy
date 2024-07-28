This example shows how to exploit the JADE Security add-on to sign and encrypt messages.
The example comprises
- a Main Container with a sender agent on top with a minimal GUI that allows sending possibly signed and encrypted messages
- a peripheral Container with a receive agent on top that prints received messages together with an indication about whether 
or not they were signed and/or encrypted

Both the Main Container and the peripheral container can be started in single-user mode or in normal (multi-user) mode.
- In single-user mode the PermissionService is not activated and the whole platform is assumed to belong to a single default user.
No policy file or user/password files are used in this case

- In multi-user mode the PermissionService is activated, the Main Container belongs to a user called alice and the peripheral container
belongs to a user called bob. 