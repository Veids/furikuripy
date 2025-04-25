<p align="center">
    <br>
    <span>Partitial implementation of furikuri in python</span>
    <br>
    <img src="images/preview.jpg"/>
</p>

# shellcode\_obfuscation

A command-line tool for obfuscating shellcode by introducing relocations, junk instructions, block rearrangements, and more. Built with iced-x86, Capstone, and furikuripy for flexible analysis and transformation.

## Installation

You can install shellcode_obfuscation via pipx:

```bash
pipx install git+https://github.com/veids/shellcode_obfuscation.git
```

## Usage

```bash
shellcode_obfuscation obfuscate [OPTIONS]
```

### Basic Options

| Option    | Short | Type       | Description                            | Default |
| --------- | ----- | ---------- | -------------------------------------- | ------- |
| `--input` | `-i`  | `FILENAME` | Input file (binary or analysis pickle) |         |

| **Required**    | Short | Type       | Description                            | Default |
| ------------------------------------------------ | ---- | ---------- | -------------------------------------------------------- | ---------------------- |
| `--output`                                       | `-o` | `FILENAME` | Output file                                              | **Required**           |
| `--input-is-analysis` / `--no-input-is-analysis` |      | Flag       | Treat input as analysis pickle rather than raw shellcode | `no-input-is-analysis` |
| `--help`                                         | `-h` | Flag       | Show this help message and exit                          |                        |

### Obfuscation Options

| Option                                                       | Type            | Description                                 | Default |
| ------------------------------------------------------------ | --------------- | ------------------------------------------- | ------- |
| `--seed`                                                     | `INTEGER`       | Random seed (dynamic if not provided)       | dynamic |
| `--relocations-allowed` / `--no-relocations-allowed`         | Flag            | Allow relocations                           | no      |
| `--complexity`                                               | `INTEGER`       | Number of passes per line                   | 3       |
| `--number-of-passes`                                         | `INTEGER (>=1)` | Total number of obfuscation passes          | 2       |
| `--junk-chance`                                              | `0–100`         | Probability (%) to insert junk instructions | 30      |
| `--block-chance`                                             | `0–100`         | Probability (%) to break code into blocks   | 30      |
| `--mutate-chance`                                            | `0–100`         | Probability (%) to mutate instructions      | 30      |
| `--forbid-stack-operations` / `--no-forbid-stack-operations` | Flag            | Disallow use of stack-based instructions    | no      |

### Analysis Options

| Option                    | Alias | Type         | Description                                                           | Default |
| ------------------------- | ----- | ------------ | --------------------------------------------------------------------- | ------- |
| `--patches`               |       | `TEXT`       | Specify patches to apply, format `start:PATCHHEX` or `index:hex`      | dynamic |
| `--arch`                  |       | `X86 \| X64` | Target architecture                                                   | None    |
| `--ranges`                |       | `TEXT`       | Define ranges for code/data blocks, e.g., `c:0:10` or `d:10:e`        | `c:0:e` |
| `--virtual-address`       |       | `INTEGER`    | Base virtual address for disassembly                                  | 0       |
| `--definitions`, `--defs` |       | `FILENAME`   | YAML file containing predefined `ranges` and `patches`                | None    |
| `--relocations`           |       | `TEXT`       | Define relocations as `<vaddress>:<type>:<symbol>`, e.g., `2:4:.data` |         |

## Examples

- Obfuscate a raw shellcode file:

  ```bash
  shellcode_obfuscation obfuscate \
    --input shellcode.bin \
    --output obf_shellcode.bin \
    --number-of-passes 3 \
    --junk-chance 40 \
    --block-chance 20
  ```

- Obfuscate using an existing analysis pickle:

  ```bash
  shellcode_obfuscation obfuscate \
    -i analysis.pkl \
    -o out.bin \
    --input-is-analysis \
    --relocations-allowed \
    --patches "0:90;10:CC"
  ```

- Specify custom ranges and relocations:

  ```bash
  shellcode_obfuscation obfuscate \
    -i shellcode.bin \
    -o obf.bin \
    --ranges "c:0:100" \
    --virtual-address 0x400000 \
    --relocations "0x10:3:.text" \
    --defs config.yaml
  ```

## License

This project is licensed under the MIT License. See `LICENSE` for details.

---

# Credits

* [furikuri](https://github.com/jnastarot/furikuri)
