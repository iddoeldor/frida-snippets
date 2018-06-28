
On the iDevice the file `/System/Library/Backup/Domains.plist` determines what files to backup.

There is a differentiation between "domains" and relative files. 

For [More Info](https://www.theiphonewiki.com/wiki/ITunes_Backup).

From `Domains.plist` :
```
...
RelativePathsToBackupAndRestore =             (
    "Demo.mov",
    "Library/com.apple.itunesstored",
    "Library/AddressBook",
    "Library/Accounts # <rdar://problem/9489580> Twitter account isn't backed up (or restored)",
    "Library/Application Support/Front Row # <rdar://problem/11427805> ATV: paths that need to be backed up on AppleTV",
    "Library/Application Support/com.apple.Home/Wallpapers # <rdar://problem/27410171>",
    "Library/BackBoard # <rdar://problem/13752515> App Push notification settings don't seem to be backed up/restored",
    "Library/BulletinBoard # <rdar://problem/9281863> Backup /var/mobile/Library/BulletinBoard",
    "Library/Caches/com.apple.WebAppCache # <rdar://problem/6500854> Should back up offline application cache and databases for WebKit",
    "Library/Calendar",
    >> "Library/CallHistoryDB # <rdar://problem/16651783> Backup request for CallHistory.framework.",
    >> "Library/CallHistoryTransactions #  <rdar://problem/16651783> Backup request for CallHistory.framework.",
    ...    
RootPath = "/var/mobile";
..
...
```

List device daemons w/ `$ launchctl list`
```
PID	Status	Label
2696	0	com.apple.CoreAuthentication.daemon
3719	0	com.apple.cloudphotod
535	0	com.apple.homed
513	0	com.apple.dataaccess.dataaccessd
-	0	com.apple.iapauthd
618	0	com.apple.cache_delete
-	0	com.apple.BTServer.avrcp
518	0	com.apple.CallHistorySyncHelper
3568	0	UIKitApplication:com.apple.InCallService[0x287]
502	0	com.apple.icloud.findmydeviced
443	0	com.apple.telephonyutilities.callservicesd
549	0	com.apple.icloud.fmfd
....
```

launchctl manual
```
Usage: launchctl <subcommand> ... | help [subcommand]
    Many subcommands take a target specifier that refers to a domain or service within that domain. 
    The available specifier forms are:

    system/[service-name]
    Targets the system-wide domain or service within. Root privileges are required to make modifications.

    user/<uid>/[service-name]
    Targets the user domain or service within. 
    A process running as the target user may make modifications. Root may modify any user's domain. 
    User domains do not exist on iOS.

    gui/<uid>/[service-name]
    Targets the GUI domain or service within. Each GUI domain is associated with a user domain, and a process running as 
    the owner of that user domain may make modifications.
    Root may modify any GUI domain. GUI domains do not exist on iOS.

    session/<asid>/[service-name]
    Targets a session domain or service within. A process running within the target security audit session may make 
    modifications. Root may modify any session domain.

    pid/<pid>/[service-name]
    Targets a process domain or service within. Only the process which owns the domain may modify it. 
    Even root may not do so.

    When using a legacy subcommand which manipulates a domain, the target domain is assumed to be the system domain. 
    On iOS, there is no support for per-user domains, even though there is a mobile user.

    Subcommands:
        ..
        debug           Configures the next invocation of a service for debugging.
        kill            Sends a signal to the service instance.
        blame           Prints the reason a service is running.
        print           Prints a description of a domain or service.
        print-cache     Prints information about the service cache.
        print-disabled  Prints which services are disabled.
        plist           Prints a property list embedded in a binary (targets the Info.plist by default).
        procinfo        Prints port information about a process.
        hostinfo        Prints port information about the host.
        runstats        Prints performance statistics for a service.
        examine         Runs the specified analysis tool against launchd in a non-reentrant manner.
        config          Modifies persistent configuration parameters for launchd domains.
        dumpstate       Dumps launchd state to stdout.
        list            Lists information about services.
        start           Starts the specified service.
        ..
    or a given subcommand.
```
Output of proccess info for CallHistorySyncHelper
`$ launchctl procinfo 549`

Added the content of referenced files (com.apple.CallHistorySyncHelper.plist)  

```
    com.apple.CallHistorySyncHelper = {
        active count = 5
        path = /System/Library/LaunchDaemons/com.apple.CallHistorySyncHelper.plist
        state = running
        program = /System/Library/PrivateFrameworks/CallHistory.framework/Support/CallHistorySyncHelper
        arguments = {
            /System/Library/PrivateFrameworks/CallHistory.framework/Support/CallHistorySyncHelper
        }
        default environment = {
            PATH => /usr/bin:/bin:/usr/sbin:/sbin
        }
        environment = {
            XPC_SERVICE_NAME => com.apple.CallHistorySyncHelper
        }
        domain = com.apple.xpc.launchd.domain.system
        username = mobile
        minimum runtime = 10
        exit timeout = 5
        runs = 1
        successive crashes = 0
        excessive crashing = 0
        pid = 518
        immediate reason = ipc (mach)
        forks = 1
        execs = 1
        trampolined = 1
        started suspended = 0
        proxy started suspended = 0
        last exit code = (never exited)
        event triggers = {
            com.apple.callhistorysync.idslaunchnotification => {
                state = 0
                service = com.apple.CallHistorySyncHelper
                stream = com.apple.notifyd.matching
                descriptor = {
                    "Notification" => "com.apple.callhistorysync.idslaunchnotification"
                }
            }
        }
        endpoints = {
            "com.apple.callhistory.pairedsync" = {
                port = 0x46907
                active = 1
                managed = 1
                reset = 0
                hide = 0
            }
            "com.apple.CallHistorySyncHelper" = {
                port = 0x46607
                active = 1
                managed = 1
                reset = 0
                hide = 0
            }
            "com.apple.CallHistorySyncHelper.aps" = {
                port = 0x4627b
                active = 1
                managed = 1
                reset = 0
                hide = 0
            }
        }
        dynamic endpoints = {
        }
        pid-local endpoints = {
        }
        instance-specific endpoints = {
        }
        event channels = {
            "com.apple.notifyd.matching" = {
                port = 0x46707
                active = 1
                managed = 1
                reset = 0
                hide = 0
            }
        }
        sockets = {
        }
        spawn type = adaptive
        jetsam priority = 3
        jetsam memory limit (active) = 6 MB
        jetsam memory limit (inactive) = 6 MB
        jetsamproperties category = daemon
        allowed to execute = 1
        submitted job. ignore execute allowed
        cpumon = default
        properties = {
            partial import = 0
            launchd bundle = 0
            xpc bundle = 0
            keepalive = 0
            runatload = 0
            dirty at shutdown = 0
            low priority i/o = 0
            low priority background i/o = 0
            exception handler = 0
            multiple instances = 0
            supports transactions = 1
            supports pressured exit = 1
            enter kdp before kill = 0
            wait for debugger = 0
            app = 0
            system app = 0
            inetd-compatible = 0
            inetd listener = 0
            abandon process group = 0
            one-shot = 0
            requires reap = 0
            event monitor = 0
            penalty box = 0
            pended non-demand spawn = 0
            role account = 0
            launch only once = 0
            system support = 0
            app-like = 0
            inferred program = 1
            ios home screen app = 0
            abandon coalition = 0
            extension = 0
            nano allocator = 0
            no initgroups = 0
            endpoints initialized = 1
            platform binary = 1
            disallow all lookups = 0
        }
    }
    program path = /System/Library/PrivateFrameworks/CallHistory.framework/Support/CallHistorySyncHelper
    Could not print Mach info for pid 518: 0x5
    bsd proc info = {
        pid = 518
        unique pid = 518
        ppid = 1
        pgid = 518
        status = stopped
        flags = 64-bit|session leader
        uid = 501
        svuid = 501
        ruid = 501
        gid = 501
        svgid = 501
        ruid = 501
        comm name = CallHistorySync
        long name = CallHistorySyncHelper
        controlling tty devnode = 0xffffffff
        controlling tty pgid = 0
    }
    pressured exit info = {
        dirty state tracked = 1
        dirty = 0
        pressured-exit capable = 1
    }
    jetsam priority = 0: idle
    jetsam memory limit = 6
    jetsam flags = (none)
    jetsam state = tracked,idle-exit
    entitlements = {
        "com.apple.private.ids.messaging" = (
            "com.apple.private.alloy.callhistorysync";
        );
        "com.apple.developer.icloud-services" = (
            "CloudKit";
        );
        "com.apple.application-identifier" = "CALLSYNCDB.com.apple.callhistory.sync-helper";
        "com.apple.developer.icloud-container-environment" = "production";
        "com.apple.private.aps-environment" = "production";
        "application-identifier" = "CALLSYNCDB.com.apple.callhistory.sync-helper";
        "aps-connection-initiate" = true;
        "com.apple.private.aps-connection-initiate" = true;
        "com.apple.private.ids.messaging.high-priority" = (
            "com.apple.private.alloy.callhistorysync";
        );
        "com.apple.accounts.appleaccount.fullaccess" = true;
        "aps-environment" = "production";
        "com.apple.private.tcc.allow" = (
            "kTCCServiceLiverpool";
            "kTCCServiceAddressBook";
        );
    };
    code signing info = valid
        ad-hoc signed
        get-task-allow entitlement
        installer entitlement
        require enforcement
        allowed mach-o
        platform dyld
        entitlements validated
        platform binary
```
Content of /System/Library/LaunchDaemons/com.apple.CallHistorySyncHelper.plist
```
{
    EnablePressuredExit = 1;
    EnableTransactions = 1;
    Label = "com.apple.CallHistorySyncHelper";
    LaunchEvents =     {
        "com.apple.notifyd.matching" =         {
            "com.apple.callhistorysync.idslaunchnotification" =             {
                Notification = "com.apple.callhistorysync.idslaunchnotification";
            };
        };
    };
    MachServices =     {
        "com.apple.CallHistorySyncHelper" = 1;
        "com.apple.CallHistorySyncHelper.aps" = 1;
        "com.apple.callhistory.pairedsync" = 1;
    };
    POSIXSpawnType = Adaptive;
    ProgramArguments =     (
        "/System/Library/PrivateFrameworks/CallHistory.framework/Support/CallHistorySyncHelper"
    );
    UserName = mobile;
}
```        
Info about `CallHistorySyncHelper`
```
$ ls -la /System/Library/PrivateFrameworks/CallHistory.framework/Support/CallHistorySyncHelper
-rwxr-xr-x  1 root wheel 279392 Aug 29  2016 CallHistorySyncHelper

$ file CallHistorySyncHelper
Mach-O 64-bit 64-bit architecture=12 executable
```

Frida REPL w/ `$ frida -U 518`

[Dump ios class hierarchy](https://github.com/iddoeldor/frida-snippets#dump-ios-class-hierarchy)
```
[iOS Device::PID::518]-> tree
{
    "NSObject": {
        "CHLogger": {
            "ApplyLocalTransactions": {},
            "CHPairedSyncCoordinator": {},
            "CHPushConnectionDelegate": {},
            "MergeTransactions": {},
            "SignalHandler": {},
            "SyncXPCServer": {}
        },
        "CHSynchronizedLoggable": {
            "AutoSync": {},
            "CHIDSPeerDevice": {},
            "CHIDSServiceDelegate": {},
            "CloudKit": {},
            "SyncEngine": {},
            "TransactionLog": {}
        },
        "PBCodable": {
            "CHRecentCallPb": {},
            "TransactionsPb": {}
        }
    }
}
```

Tried to print `ObjC.classes.AutoSync` and the daemon shut down
```
PID	Status	Label
-	-43	com.apple.CallHistorySyncHelper
```
Get binary w/ Frida
```
cmd = Shell(['/bin/sh', '-c', "cat /System/Library/PrivateFrameworks/CallHistory.framework/Support/CallHistorySyncHelper"], None)
cmd.exec()/push
with open('~/CallHistorySyncHelper', 'wb+') as f:
    f.writelines(cmd.output)
```
