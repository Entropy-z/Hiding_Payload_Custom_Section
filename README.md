# Hiding_Payload_Custom_Section
Demostration of how to insert a custom PE section and retrieve payload in custom section. 

The project is included two archives, the **inserter.c** and **target.c**.

## inserter.c
The inserter.c create section in the remote PE with payload/shellcode. 

## target.c
The target.c retrive payload/shellcode in the new section created.

## calc.bin
Payload used for test.

## Usage
```sh
.\inserter.exe -e <PE> -p <shellcode/payload.bin> -s <new section name>
```

For more information, visit my journal: https://oblivions-research.gitbook.io/
