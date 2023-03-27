# IntuneStatusPage

The StatusPage serves to be a simple variant to inform the user about a running Intune installation.
The app should be as small as possible to be able to pass it as a base64 string in the script.

## usage from commandline

Run IntuneStatusPage from commandline:

- Time in seconds
- blure / black
- Title

```bash
./IntuneStatusPage 60 blure "MyTitle"
```

## use runIntuneStatusPage.sh

Deploy the demo script with Intune and run it as root.
If you want to create and distribute a custom variant of the scirpt you have to build it first. For this you need the xcode developer tools.
Customize the IntuneStatusPage as you like. Then execute the following command to compile the Swift file.

```bash
swiftc IntuneStatusPage.swift
```

The finished script can now be distributed.
To do it the same way as I did in runIntuneStatusPage.sh, it must be base64 encoded. To do this enter the following command:

```bash
cat IntuneStatusPage | base64 
```

This can be decoded with the following command:

```bash
echo "<base64 string>" | base64 --decode > "<path>"
```

## screenshots
![Screenshot 1](ScreenShot1.png?raw=true "Title")
![screenshot 2](ScreenShot2.png?raw=true "Title")