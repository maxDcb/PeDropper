# PeDropper

**PeDropper** is a Python-based tool that generates a dropper executable (EXE) and DLL to execute a PE binary or inject raw shellcode. It simplifies payload creation for red team operations, malware simulation, or post-exploitation tasks.

This dropper is integrated as a module in the [Exploration C2](https://github.com/maxDcb/C2TeamServer) framework.

## Features

* Embed and execute a PE binary inside a generated dropper
* Pass command-line arguments to the embedded binary
* Support for injecting raw shellcode directly
* Outputs both EXE and DLL versions of the dropper

## Usage

```bash
PeDropper.py -b <path_to_binary> [-a "<arguments>"]
PeDropper.py -r <path_to_raw_shellcode>
```

### Options

* `-h`
  Show the help message and exit.

* `-b, --binary <path>`
  Path to the PE binary to embed and execute (e.g., `C:\Windows\System32\calc.exe` or `./calc`).

* `-a, --args "<args>"`
  Optional command-line arguments to pass to the binary.

* `-r <path>`
  Path to a raw shellcode file to inject into the dropper instead of a PE binary.

## Examples

```bash
# On Windows: generate a dropper for calc.exe
PeDropper.py -b C:\Windows\System32\calc.exe

# On Linux: generate a dropper for calc with arguments
PeDropper.py -b ./calc -a "-flag1 -flag2"

# Generate a dropper that injects raw shellcode
PeDropper.py -r ./payload.raw
```

## Notes

* Either `--binary` or `-r` (shellcode) must be provided, but not both.
* Ensure any shellcode or PE binary used is compatible with the target environment.

## Disclaimer

This tool is intended for authorized security research and red teaming only. Unauthorized use is strictly prohibited.
