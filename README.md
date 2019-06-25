# Felix: Extended Features

This repository will be used to devlop/release the extended features for the
Felix project.


## Purpose

The purpose of the Felix project is to develop SwitchDev and TSN support for
ethernet switching Chips, and ethernet switching IP-cores.

SwitchDev is driver layer in the Linux kernel, where they have abstracted how to
model a switch inside the kernel.

The features supported by SwitchDev is still limited, and it currently does not
have any TSN support.

The purpose of this repository, is to develop the extended features as defined
in the Felix project. This includes ACL, QoS and the TSN features.


## Architecture

The main facility offered by this repository is a set of header files describing
the sub-set of the features which will not be provided as part of the SwitchDev
framework.

These header files can be used by a user-space application, a library
implementing these header files will communicate with the Linux kernel, and make
the kernel apply configuration (or query status) from the HW.

The initial development of the kernel driver for the extended features, will be
done in a kernel module, but may at a later point in time be moved in in-tree
development.

Beside from offering a library to reach the extended features, the repository
will also offer a simple command-line test application that allow to read
status and apply static configuration. This application will not implement any
protocols, but only offer an easy way to _call_ the various function in the
kernel. This application will be used when doing test and validation of the
features developed in the kernel.

The call-stack looks like this:

                 +-----------+
                 |  Felix    |  +--+  +------+
                 |   test    |  |tc|  |bridge|
                 |application|  +--+  +------+
                 +-----------+    ^      ^
                 | libfelix  |    |      |
                 +-----------+    |      |
                      ^           |      |
                      |           |      |
    User-space        |           |      |
    -----------------(|)---------(|)----(|)----
    Kernel-space      |           |      |
                      |           |      |
                      v           v      v
                  +--------+    +-----------+
                  | Felix  |    |   Felix   |
                  |Extended|    | SwitchDev |
                  |Features|    |   Driver  |
                  +--------+    +-----------+
                      ^               ^
                      |               |
                      v               v
                  +----------------------------+
                  |Mutual-exclusive-chip-access|
                  +----------------------------+
                                ^
    Kernel-space                |
    -----------------------------------
    Hardware                    |
                                v


Multiple user-space application can use the `libfelix` library simultaneous.

Communication between user-space and kernel space is done by using netlink. The
existing tools will be using the existing netlink interfaces, while the extended
features will be using a generic-netlink interface.


