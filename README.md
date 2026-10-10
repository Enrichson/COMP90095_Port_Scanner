Port Scanner & Banner Grabber

Subject: COMP90095 – Assessment 3 Author: Enrichson Paris (Student ID: 1861085)

Purpose

A Python program that scans a host for common open TCP ports, grabs the first 100 bytes of each service's banner to identify what is running, and saves a summary report to a text file.

Requirements
Python 3.8 or later
No external libraries (standard library only)
How to run
bash
python3 port_scanner.py

Enter a hostname when prompted, or press Enter to scan localhost. The report is saved as scan_report_<hostname>_<date>_<time>.txt.

Ethical use

Please only scan hosts you own or have permission to scan: localhost, comp90095.cis.unimelb.edu.au or scanme.nmap.org.