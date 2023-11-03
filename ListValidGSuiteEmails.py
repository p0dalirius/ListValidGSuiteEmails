#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ListValidGSuiteEmails.py
# Author             : Podalirius (@podalirius_)
# Date created       : 9 Dec 2021

import argparse
import datetime
import json
import os
import traceback
import requests
import sqlite3
import sys
import threading
import time
import xlsxwriter
from concurrent.futures import ThreadPoolExecutor


VERSION = "1.1"


def export_xlsx(data, path_to_file):
    print("[>] Writing '%s' ... " % path_to_file, end="")
    sys.stdout.flush()
    basepath = os.path.dirname(path_to_file)
    filename = os.path.basename(path_to_file)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename

    workbook = xlsxwriter.Workbook(path_to_file)
    worksheet = workbook.add_worksheet()

    header_format = workbook.add_format({'bold': 1})
    header_fields = ["Email"]
    for k in range(len(header_fields)):
        worksheet.set_column(k, k + 1, len(header_fields[k]) + 3)
    worksheet.set_row(0, 20, header_format)
    worksheet.write_row(0, 0, header_fields)

    row_id = 1
    for email in data:
        worksheet.write_row(row_id, 0, [
            email,
        ])
        row_id += 1
    worksheet.autofilter(0, 0, row_id, len(header_fields) - 1)
    workbook.close()
    print("done.")


def export_json(data, path_to_file):
    print("[>] Writing '%s' ... " % path_to_file, end="")
    sys.stdout.flush()
    basepath = os.path.dirname(path_to_file)
    filename = os.path.basename(path_to_file)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename
    f = open(path_to_file, 'w')
    f.write(json.dumps({"emails": data}, indent=4))
    f.close()
    print("done.")


def export_sqlite(data, path_to_file):
    print("[>] Writing '%s' ... " % path_to_file, end="")
    sys.stdout.flush()
    basepath = os.path.dirname(path_to_file)
    filename = os.path.basename(path_to_file)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename

    conn = sqlite3.connect(path_to_file)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS results(email VARCHAR(512));")
    for email in data:
        cursor.execute("INSERT INTO results VALUES (?)", (
                email,
            )
        )
    conn.commit()
    conn.close()
    print("done.")


def monitor_thread(options, monitor_data, only_check_finished=False):
    time.sleep(1)
    last_check, monitoring = 0, True
    while monitoring:
        new_check = monitor_data["actions_performed"]
        rate = (new_check - last_check)
        monitor_data["lock"].acquire()
        if monitor_data["total"] == 0:
            print("\r[%s] Status (%d/%d) %5.2f %% | Rate %d tests/s        " % (
                    datetime.datetime.now().strftime("%Y/%m/%d %Hh%Mm%Ss"),
                    new_check, monitor_data["total"], 0,
                    rate
                ),
                end=""
            )
        else:
            print("\r[%s] Status (%d/%d) %5.2f %% | Rate %d tests/s        " % (
                    datetime.datetime.now().strftime("%Y/%m/%d %Hh%Mm%Ss"),
                    new_check, monitor_data["total"], (new_check / monitor_data["total"]) * 100,
                    rate
                ),
                end=""
            )
        last_check = new_check
        monitor_data["lock"].release()
        time.sleep(1)
        if only_check_finished:
            if monitor_data["finished"]:
                monitoring = False
        else:
            if rate == 0 and monitor_data["actions_performed"] == monitor_data["total"] or monitor_data["finished"]:
                monitoring = False
    print()


def check_if_email_exists(email, options, request_proxies, monitor_data):
    try:
        r = requests.get(
            f"https://mail.google.com/mail/gxlu?email={email}",
            timeout=options.request_timeout,
            proxies=request_proxies
        )
        if r.status_code == 204:
            if any([cookie.name == "COMPASS" for cookie in r.cookies]):
                if r.headers["Set-Cookie"]:
                    monitor_data["emails"].append(email)
                    if options.no_colors:
                        print("\x1b[2K\r[+] Valid email: %s" % (email))
                    else:
                        print("\x1b[2K\r[+] Valid email: \x1b[1;92m%s\x1b[0m" % (email))

    except Exception as e:
        traceback.print_exc()

    monitor_data["actions_performed"] += 1

    return None


def parseArgs():
    print("ListValidGSuiteEmails.py v%s - by @podalirius_\n" % VERSION)

    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    parser.add_argument("--debug", default=False, action="store_true", help="Debug mode, for huge verbosity. (default: False)")
    parser.add_argument("-T", "--threads", default=16, type=int, help="Number of threads (default: 16)")
    parser.add_argument("--no-colors", default=False, action="store_true", help="Disable colored output. (default: False)")

    group_configuration = parser.add_argument_group("Advanced configuration")
    group_configuration.add_argument("-PI", "--proxy-ip", default=None, type=str, help="Proxy IP.")
    group_configuration.add_argument("-PP", "--proxy-port", default=None, type=int, help="Proxy port.")
    group_configuration.add_argument("-rt", "--request-timeout", default=5, type=int, help="Set the timeout of HTTP requests.")

    group_export = parser.add_argument_group("Export results")
    group_export.add_argument("--export-xlsx", dest="export_xlsx", type=str, default=None, required=False, help="Output XLSX file to store the results in.")
    group_export.add_argument("--export-json", dest="export_json", type=str, default=None, required=False, help="Output JSON file to store the results in.")
    group_export.add_argument("--export-sqlite", dest="export_sqlite", type=str, default=None, required=False, help="Output SQLITE3 file to store the results in.")

    group_emails_source = parser.add_argument_group("Emails")
    group_emails_source.add_argument("-ef", "--emails-file", default=None, type=str, help="Path to file containing a line by line list of emails.")
    group_emails_source.add_argument("-E", "--email", default=[], type=str, action='append', help="Email.")
    group_emails_source.add_argument("--stdin", default=False, action="store_true", help="Read emails from stdin. (default: False)")
    group_emails_source.add_argument("-c", "--csv-names", default=None, type=str, help="Path to file containing a line by line list of first and last names.")
    group_emails_source.add_argument("-d", "--domain", type=str, help="Add this domain to the emails.")
    

    options = parser.parse_args()

    if (options.emails_file is None) and (options.stdin == False) and (len(options.email) == 0) and ((options.csv_names is None) and (options.domain is None)):
        parser.print_help()
        print("\n[!] No emails specified.")
        sys.exit(0)

    elif (options.csv_names is not None) and (options.domain is None) :
        parser.print_help()
        print("\n[!] Option --domain is required with --csv-names.")
        sys.exit(0)

    return options


if __name__ == '__main__':
    options = parseArgs()

    request_proxies = {}
    if options.proxy_ip is not None and options.proxy_port is not None:
        request_proxies = {
            "http": "http://%s:%d/" % (options.proxy_ip, options.proxy_port),
            "https": "https://%s:%d/" % (options.proxy_ip, options.proxy_port)
        }

    emails_to_check = []

    # Loading emails line by line from file
    if options.emails_file is not None:
        if os.path.exists(options.emails_file):
            if options.debug:
                print("[debug] Loading emails line by line from file '%s'" % options.emails_file)
            f = open(options.emails_file, "r")
            for line in f.readlines():
                emails_to_check.append(line.strip())
            f.close()
        else:
            print("[!] Could not open emails file '%s'" % options.emails_file)

    # Loading names line by line from file
    if options.csv_names is not None:
        if os.path.exists(options.csv_names):
            if options.debug:
                print("[debug] Loading names line by line from file '%s'" % options.csv_names)
            f = open(options.csv_names, "r")
            for line in f.readlines():
                firstname, lastname = line.lower().strip().split(';')[:2]
                emails_to_check.append(f"{firstname}.{lastname}@{options.domain}")
                emails_to_check.append(f"{lastname}@{options.domain}")
                emails_to_check.append(f"{firstname}@{options.domain}")
                emails_to_check.append(f"{firstname[0]}{lastname}@{options.domain}")
            f.close()
        else:
            print("[!] Could not open names file '%s'" % options.csv_names)

    # Loading emails from a single --email option
    if len(options.email) != 0:
        if options.debug:
            print("[debug] Loading emails from --email options")
        for email in options.email:
            emails_to_check.append(email)

    final_emails = []
    for email in emails_to_check:
        if '@' in email:
            final_emails.append(email.lower().strip())
        else:
            if options.domain is not None:
                final_emails.append(email.lower().strip() + '@' + options.domain)
            else:
                pass
    emails_to_check = sorted(list(set(final_emails)))

    if len(emails_to_check) != 0:
        print("[>] Checking %d emails if they exists" % len(emails_to_check))
        monitor_data = {"actions_performed": 0, "total": len(emails_to_check), "emails": [], "lock": threading.Lock(), "finished": False}
        with ThreadPoolExecutor(max_workers=min(options.threads, (len(emails_to_check)+1))) as tp:
            tp.submit(monitor_thread, options, monitor_data, False)
            for email in emails_to_check:
                tp.submit(check_if_email_exists, email, options, request_proxies, monitor_data)

        if options.export_xlsx is not None:
            export_xlsx(monitor_data["emails"], options.export_xlsx)

        if options.export_json is not None:
            export_json(monitor_data["emails"], options.export_json)

        if options.export_sqlite is not None:
            export_sqlite(monitor_data["emails"], options.export_sqlite)

        print("[>] All done!")

    elif options.stdin:
        print("[>] Checking emails from stdin if they exists")
        monitor_data = {"actions_performed": 0, "total": 0, "emails": [], "lock": threading.Lock(), "finished": False}
        with ThreadPoolExecutor(max_workers=options.threads) as tp:
            tp.submit(monitor_thread, options, monitor_data, True)
            try:
                while True:
                    email = input()
                    monitor_data["total"] += 1
                    tp.submit(check_if_email_exists, email, options, request_proxies, monitor_data)
            except EOFError as e:
                pass

        if options.export_xlsx is not None:
            export_xlsx(monitor_data["emails"], options.export_xlsx)

        if options.export_json is not None:
            export_json(monitor_data["emails"], options.export_json)

        if options.export_sqlite is not None:
            export_sqlite(monitor_data["emails"], options.export_sqlite)

        print("[>] All done (%d emails checked)!" % (monitor_data["actions_performed"]))

    else:
        print("[!] No emails to find.")

