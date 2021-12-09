![](./.github/banner.png)

<p align="center">
    A Python script to list valid emails of GSuite accounts.
    <br>
    <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/ListValidGSuiteEmails">
    <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
    <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
    <br>
</p>

## Features

 - [x] Find valid Google Suite emails from a list of probable emails.
 - [x] Export results in JSON with `--export-json <file.json>`.
 - [x] Export results in XLSX with `--export-xlsx <file.xlsx>`.
 - [x] Export results in SQLITE3  with `--export-sqlite <file.db>`.

## Usage

```
$ ./ListValidGSuiteEmails.py -h
ListValidGSuiteEmails.py v1.1 - by @podalirius_

usage: ListValidGSuiteEmails.py [-h] [-v] [--debug] [-T THREADS] [--no-colors] [-PI PROXY_IP] [-PP PROXY_PORT] [-rt REQUEST_TIMEOUT]
                                [--export-xlsx EXPORT_XLSX] [--export-json EXPORT_JSON] [--export-sqlite EXPORT_SQLITE]
                                [-ef EMAILS_FILE] [-E EMAIL] [-d DOMAIN] [--stdin]

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode. (default: False)
  --debug               Debug mode, for huge verbosity. (default: False)
  -T THREADS, --threads THREADS
                        Number of threads (default: 16)
  --no-colors           Disable colored output. (default: False)

Advanced configuration:
  -PI PROXY_IP, --proxy-ip PROXY_IP
                        Proxy IP.
  -PP PROXY_PORT, --proxy-port PROXY_PORT
                        Proxy port.
  -rt REQUEST_TIMEOUT, --request-timeout REQUEST_TIMEOUT
                        Set the timeout of HTTP requests.

Export results:
  --export-xlsx EXPORT_XLSX
                        Output XLSX file to store the results in.
  --export-json EXPORT_JSON
                        Output JSON file to store the results in.
  --export-sqlite EXPORT_SQLITE
                        Output SQLITE3 file to store the results in.

Emails:
  -ef EMAILS_FILE, --emails-file EMAILS_FILE
                        Path to file containing a line by line list of emails.
  -E EMAIL, --email EMAIL
                        Email.
  -d DOMAIN, --domain DOMAIN
                        Add this domain to the emails.
  --stdin               Read emails from stdin. (default: False)
```

## Quick win commands

 + Find valid emails from a list of possible emails read from a file:
    ```
    ./ListValidGSuiteEmails.py -ef possible_emails.txt
    ```

 + Find valid emails from a list of possible email format read from a file and add the @domain afterwards:
    ```
    ./ListValidGSuiteEmails.py -ef possible_email_formats.txt -d podalirius.net
    ```
 
 + Check if a single email is valid:
    ```
    ./ListValidGSuiteEmails.py -E areyouvalid@podalirius.net
    ```

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

## References

 - https://blog.0day.rocks/abusing-gmail-to-get-previously-unlisted-e-mail-addresses-41544b62b2
