# RBXFFlagDumper

**RBXFFlagDumper** is a lightweight, low-level utility designed to extract and display **Roblox FFlags** (Feature Flags) directly from a running Roblox client process. By reading process memory in real time, it gives developers, reverse engineers, and power users an unfiltered snapshot of all active flags and their current states—bypassing the need for external debuggers or manual inspection.

---

## Features

- **Real‑time Flag Extraction** – Dumps all active Roblox FFlags directly from the client’s memory space.
- **Minimal & Efficient** – Written in pure C++ with no external dependencies; fast and lightweight.
- **Process Memory Access** – Uses Windows API low‑level memory reading techniques to retrieve flag data reliably.
- **Visual Studio Ready** – Includes pre‑configured `.sln` and `.vcxproj` files for one‑click compilation.
- **Clean Output** – Formats flags in a human‑readable list for quick analysis.

---

## Getting Started

### Prerequisites

- **Operating System** – Windows (the Roblox client runs on Windows).
- **Compiler** – Visual Studio 2019 or later (Community edition works fine).
- **Knowledge** – Basic C++ understanding if you intend to modify or extend the tool.

### Building from Source

1. **Clone the repository**
   ```bash
   git clone https://github.com/hcrdso/RBXFFlagDumper.git
   cd RBXFFlagDumper
Open the solution

Double‑click fflag dumper.sln to launch Visual Studio.

Build the project

Select your desired configuration (Debug / Release) and platform (x86 / x64).

Press Ctrl+Shift+B or go to Build → Build Solution.

Locate the executable

The output .exe will be placed in the standard Visual Studio output folder (e.g., x64\Release\).

##Usage
Important: This tool reads the memory of a running Roblox process. Ensure you have the necessary system permissions and are fully aware of Roblox’s Terms of Service. Use only for educational and research purposes.

Launch Roblox – Open any experience and let the client fully load.

Run the dumper – Execute the compiled RBXFFlagDumper.exe.

View the output – The tool will attach to the Roblox process, scan memory for FFlag structures, and print all flags with their current boolean/numeric values to the console.

Example output snippet:

FFlag::DebugPhysicsEnabled = true
FFlag::NewRenderingPipeline = false
FFlag::EnableExperimentalUI = true
...
## Dependencies
Windows API – Used for process enumeration, opening handles, and ReadProcessMemory.

C++ Standard Library – For strings, containers, and I/O.

No third‑party libraries are required – the tool is completely self‑contained.

##Contributing
Contributions are highly appreciated! Whether it’s a bug fix, performance improvement, or new feature:

Open an issue – Discuss your idea or report a problem.

Fork the repo – Create your own fork and work on a feature branch.

Submit a pull request – Provide a clear description of your changes and why they matter.

Please maintain the existing code style and include comments where necessary.

---

## License
This project is licensed under the MIT License – see the LICENSE file for full details.

---

## Disclaimer
This tool is not affiliated with, endorsed by, or sponsored by Roblox Corporation. It is provided as‑is for educational and research purposes only. The authors assume no liability for any misuse, account restrictions, or violations of Roblox’s Terms of Service that may result from using this software. Use at your own risk.
