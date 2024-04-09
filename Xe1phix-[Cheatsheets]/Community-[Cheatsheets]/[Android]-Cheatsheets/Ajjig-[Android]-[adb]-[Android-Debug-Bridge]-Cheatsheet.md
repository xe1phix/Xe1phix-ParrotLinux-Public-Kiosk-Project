# ADB CHEATSHEET
ADB (Android Debug Bridge) is a versatile command-line tool that lets you communicate with a device. The adb command facilitates a variety of device actions, such as installing and debugging apps, and it provides access to a Unix shell that you can use to run a variety of commands on a device. It is a client-server program that includes three components: ([See documentation](https://developer.android.com/studio/command-line/adb))

- A client, which sends commands. The client runs on your development machine. You can invoke a client from a command-line terminal by issuing an adb command.
- A daemon (adbd), which runs commands on a device. The daemon runs as a background process on each device.
- A server, which manages communication between the client and the daemon. The server runs as a background process on your development machine.

## Basic commands
|               Command                       |                    Uses                    |
|:-------------------------------------------:|:------------------------------------------:|
| adb devices                                 | lists connected devices                    |
| adb root                                    | restarts adbd with root permissions        |
| adb start-server                            | starts the adb server                      |
| adb kill-server                             | kills the adb server                       |
| adb reboot                                  | reboots the device                         |
| adb devices -l                              | list of devices by product/model           |
| adb shell                                   | starts the backround terminal              |
| exit                                        | exits the background terminal              |
| adb help                                    | list all commands                          |
| adb -s {deviceName} {command}               | redirect command to specific device        |
| adb –d {command}                            | directs command to only attached USB device|
| adb –e {command}                            | directs command to only attached emulator  |

## Apps installation
```bash
adb shell install {apk_path}  : install app (.apk)
adb shell install {app_path}  : install app from phone path
adb shell install -r {path}   : install app from phone path
adb shell uninstall {app_name}: remove the app
```

## File Operations
|               Command                       |                    Uses                    |
|:-------------------------------------------:|:------------------------------------------:|
| adb push {local} {remote}                   | copy file/dir to device                    |
| adb pull {remote} {local}                   | copy file/dir from device                  |
| run-as {package} cat {file}                 | access the private package files           |

## Device Info
|               Command                       |                    Uses                    |
|:-------------------------------------------:|:------------------------------------------:|
| adb get-statе                                   | print device state                                  |
| adb get-serialno                                | get the serial number                               |
| adb shell dumpsys iphonesybinfo                 | get the IMEI                                        |
| adb shell netstat                               | list TCP connectivity                               |
| adb shell pwd                                   | print current working directory                     |
| adb shell dumpsys battery                       | battery status                                      |
| adb shell pm list features                      | list device features                                |
| adb shell service list                          | list all services                                   |
| adb shell dumpsys activity {package}/{activity} | activity info                                       |
| adb shell ps                                    | print process status                                |
| adb shell wm size                               | displays the current screen resolution              |
| dumpsys window windows \| grep -E 'mCurrentFocus \| mFocusedApp' | print current app's opened activity |

## Package Info
|               Command                       |                    Uses                    |
|:-------------------------------------------:|:------------------------------------------:|
adb shell list packages            | list package names                                    |
adb shell list packages -r         | list package name + path to apks                      |
adb shell list packages -3         | list third party package names                        |
adb shell list packages -s         | list only system packages                             |
adb shell list packages -u         | list package names + uninstalled                      |
adb shell dumpsys package packages | list info on all apps                                 |
adb shell dump {name}              | list info on one package                              |
adb shell path {package}           | path to the apk file                                  |

## Settings Commands
|               Command                       |                    Uses                    |
|:-------------------------------------------:|:------------------------------------------:|
| adb shell dumpsys battery set level {n} | change the level from 0 to 100                 |
| adb shell dumpsys battery set status{n} | change the level to unknown, charging, discharging, not charging or full |
| adb shell dumpsys battery reset         | reset the battery                              |
| adb shell dumpsys battery set usb {n}   | change the status of USB connection. ON or OFF |
| adb shell wm size WxH                   | sets the resolution to WxH                     |

## Device Commands
 
|               Command                       |                    Uses                    |
|:-------------------------------------------:|:------------------------------------------:|
| abd connect HOST:PORT                       | connect to device wirelessly (same network)|
| adb reboot-recovery                         | reboot device into recovery mode           |
| adb reboot fastboot                         | reboot device into recovery mode           |
| adb shell screencap -p "example.png"        | take a screenshot                          |
| adb shell screenrecord "example.mp4"        | record device screen                       |
| adb backup -apk -all -f backup.ab           | backup settings and apps                   |
| adb backup -apk -shared -all -f backup.ab   | backup settings & apps & shared storage    |
| adb backup -apk -nosystem -all -f backup.ab | backup only user-installed apps            |
| adb restore backup.ab                       | restore the previous backups               |


## Permissions
|               Command                       |                    Uses                    |
|:-------------------------------------------:|:------------------------------------------:|
| adb shell permissions groups                | list permission groups definitions         |
| adb shell list permissions -g -r            | list permissions details                   |

## PATHs
```

└───/data/
└───└─── /data/<package>/databases (app databases)
└───└─── /data/<package>/shared_prefs/ (shared preferences)
└───└─── /app (apk installed by user)
└─── /system/app (pre-installed APK files)
└─── /mnt/
└───└─── /asec (encrypted apps) (App2SD)
└───└─── /emmc (internal SD Card)
└───└─── /adcard (external/Internal SD Card)
└───└─── /adcard/external_sd (external SD Card)
```

adb shell ls (list directory contents)
adb shell ls -s (print size of each file)
adb shell ls -R (list subdirectories recursively)

