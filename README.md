# WinDbgX - BYOVD Toolkit
This project implements a "Bring Your Own Vulnerable Driver" (BYOVD) attack that exploits a vulnerable driver for kernel mode access that is not in the [vulnerable driver block lists](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) or known to any EDR vendors. With local admin access, an operator can run this tool to disable EDR telemetry and run any commands, drop any files, and access any resources without knowledge or interference of the EDR.

In addition to an "unknown vulnerable driver", this tool also uses a side channel bypass to load the driver, so it avoids noisy kernel service creation IOCs. 

## Requirements
- Local admin access (to load the driver)
- System requirements:
  - Must be newer than Windows 7 (not tested on 8.1 or earlier)
  - The IORING method is not implemented. This was added in Windows 11 and I have the exploit and 0day driver to be added, it's just not ported over yet.

## Notes
- Certain features are noisier and may lead to detection:
  - Downloading a PDB file (this project downloads it to _memory_, not to disk...so it helps but still can be detected)
  - Starting a kernel service (not _creating_, though, so much harder to detect)
  - May trigger some machine learning/AI detections by the simple fact of it being a nonstandard binary.

## Recommendations
- If you can, add the driver and start the service manually before running the binary. 
  - This will be less sus than doing it in the process.
  - The code will check if it's loaded. If not, it will write the driver to disk, modify the kernel service, and start it before continuing. Each of these could be noted by the EDR.
- Let the binary sit for a while before running it, especially if you're transferring via SMB or something.
