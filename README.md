# Mini Hypervisor – C/C++ Virtualization Project

A lightweight KVM-based hypervisor implemented in C/C++, designed to manage single or multiple virtual machines (VMs) with basic virtual I/O support.
The project demonstrates low-level systems programming, POSIX threading, and modular architecture for virtualization.

## ✨ Key Features

🖥️ Virtual Machine Management

- Launch and terminate single or multiple VMs
- Modular VM lifecycle operations: initialize, configure, start, stop
- Virtualized CPU, memory, and I/O handling

⚙️ POSIX Threading

- Separate threads for VM execution, I/O handling, and scheduler management
- Ensures concurrency and responsiveness
- Demonstrates safe synchronization and resource sharing

💾 Virtual I/O

- Basic emulated devices for VMs
- Handles input/output requests from guest VMs
- Extensible architecture for adding new virtual devices

📦 Build System

- Makefile included for automated building and compilation
- Modular compilation structure for easy maintenance and extensions

📚 Learning Goals

- Low-level systems programming with C/C++
- Understanding of virtualization concepts and kernel modules
- Hands-on experience with KVM API and VM lifecycle management
- Multithreading and synchronization in a concurrent system

## 🛠️ Technologies Used

- C / C++
- KVM for virtualization
- POSIX threads
- Linux environment required
- Makefile for automated build
  
