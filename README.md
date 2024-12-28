# AME Wizard Core

Core functionality used by AME Wizard.

## CLI Usage

*We do not recommend CLI usage for normal users, instead use [AME Wizard](https://ameliorated.io/).*

1. Download `CLI-Standalone.zip` from the [latest release](https://github.com/Ameliorated-LLC/trusted-uninstaller-cli/releases/latest)

2. Extract the downloaded archive

3. Inside the extracted folder, place a Playbook of choice

4. Extract the Playbook with 7zip using the password `malte`

5. Open **Command Prompt** as administrator and navigate to the extracted CLI-Standalone folder

6. Run `TrustedUninstaller.CLI.exe "<Extracted Playbook Folder>"`

   Optionally, you can specify options like in the following example:
   ```
   TrustedUninstaller.CLI.exe "AME 11 v0.7" browser-firefox enhanced-security
   ```

## Running the Wizard Offline

To run the AME Wizard without an internet connection, follow these steps:

1. Ensure you have downloaded the required dependencies beforehand using the pre-download script (see below).

2. Follow the steps in the CLI Usage section above to set up the AME Wizard.

3. When running the wizard, it will check for an internet connection. If not connected, it will provide a warning and proceed with limited functionality.

## Using the Pre-Download Script

To pre-download the required dependencies for running the AME Wizard offline, follow these steps:

1. Download the pre-download script from the [latest release](https://github.com/Ameliorated-LLC/trusted-uninstaller-cli/releases/latest).

2. Extract the downloaded archive.

3. Open **Command Prompt** as administrator and navigate to the extracted folder.

4. Run the pre-download script:
   ```
   pre-download-script.bat
   ```

5. The script will download the required dependencies and save them in the appropriate folder for offline use.

## Compilation

1. Clone the repository
   ```
   git clone https://github.com/Ameliorated-LLC/trusted-uninstaller-cli.git
   ```
2. Open TrustedUninstaller.sln with Visual Studio or JetBrains Rider

3. Set the configuration to **Release**

4. Build TrustedUninstaller.CLI

## License
This tool has an [MIT license](https://en.wikipedia.org/wiki/MIT_License), which waives any requirements or rules governing the source code’s use, removing politics from the equation.

Since this project makes major alterations to the operating system and has the ability to install software during this process, it is imperative that we **provide its source code for auditing purposes.**  
This has not only helped us build trust, and make our project stand out among the crowd, but has also led to many community contributions along the way.
