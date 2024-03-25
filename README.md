# Hiding_Payload_Custom_Section
Demostration of how to insert a custom PE section and retrieve payload in custom section. 

O projeto é composto de dois arquivos, o **inserter.c** e o **target.c**.

## inserter.c
The inserter.c create section in the remote PE with payload/shellcode. 

## target.c
The target.c retrive payload/shellcode in the new section created.

## calc.bin
Payload used for test.

## Usage
```sh
.\inserter.exe -p <shellcode/payload.bin> -s <new section name> -e <pe path> -o <output pe name>
```

For more information, visit my journal: https://oblivions-research.gitbook.io/
