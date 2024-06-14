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