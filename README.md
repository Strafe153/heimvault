# Heimvault 🛡️

Heimvault is a minimalist, efficient command-line secret manager. It is written in the [Odin programming language](https://odin-lang.org/) and leverages **Libsodium** for industry-standard, "misuse-resistant" cryptography.

## Prerequisites

To build and run Heimvault, you must have the **Odin compiler** installed and the **Libsodium** development files available on your system.

### Install Libsodium
* **Ubuntu/Debian:** `sudo apt install libsodium-dev`

## Local Build Instructions

Run the following command from the project root:

```bash
odin build src -out:heimvault -o:speed
```

## Disclaimer

Even though the program aims to be useful, it is distributed under the MIT License WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.  
The users are solely responsible for determining the appropriateness of using or redistributing the Work and assume any risks associated with their exercise of permissions under the License.