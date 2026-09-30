# SSL/TLS Certificate Watcher

This package is a command-line tool for monitoring SSL/TLS certificates that your network services present to clients. It connects to a list of service endpoints, including direct TLS services and endpoints that require STARTTLS, captures certificate details, and checks whether each certificate is currently valid or approaching expiration.

The tool uses a YAML configuration file to define the monitored endpoints, warning and critical expiration thresholds, and notification destinations. You can filter by which threshold groups (good, warning, critical) that you report on.

```sh
$ cert-watcher -c config.yaml --console

Critical Certificates:
  Certificate for api.rest.example.com:8123
    Description: REST API for example.com
    Subject: CN=api.rest.example.com
    Started: 83 days ago
    Expires: 2026-10-04 06:21:05+00:00, (6 days left)

Warning Certificates:
  Certificate for www.example.com:443
    Description: Website example.com
    Subject: CN=www.example.com
    Started: 70 days ago
    Expires: 2026-10-27 06:29:02+00:00, (19 days left)

Good Certificates:
  Certificate for mail.example.com:25 (starttls: smtp)
    Description: External SMTP server
    Subject: CN=mail.example.com
    Started: 45 days ago
    Expires: 2026-11-11 06:04:38+00:00, (44 days left)
```

This is copyrighted software; see the `LICENSE` file for details about the license under which it is made available to you.


## Installation

### Runtime Only

If you just want to use the tool and don't want to do any development with it, this section is for you.

You only need the Python wheel (`*.whl`) file and your favorite way to install it.

If you want to install it with [the 'uv' tool](https://github.com/astral-sh/uv) from [Astral](https://astral.sh/), check that you have installed uv on your system and then run:

```sh
uv tool install /path/to/certificate-watcher-{version}-py3-none-any.whl
```
Note that `{version}` changes with each new release.

When you install the distribution wheel on your system, you will run the tool with the `cert-watcher` command. 


### Development Setup

If you are curious about the code, want to tinker with it, or want to send me your awesome pull requests, this section is for you.

1. Install [the 'uv' tool](https://github.com/astral-sh/uv) from [Astral](https://astral.sh/).
1. Install package dependencies:
    - Basic use: `uv sync`, or
    - Extra development packages: `uv sync --extra dev`

When you run this tool through 'uv', you will use `uv run cert-watcher` from the top-level of the project source directory. The included VSCode files also run from the source directory.


## Configuration

Each execution is controlled by a YAML configuration file. You can create different runtime profiles using different configuration files and separate runs of the tool.

Refer to the example configuration file: `example-config.yaml`.

Overview of the configuration sections:
```yaml
watch:

config:

notifications:
  source:

  destinations:
```

### Section: 'watch'

This is a list of the endpoints whose TLS certificates you want to watch. Each item in the list has these elements:

- `id` -- unique key for each item
- `description` -- descriptive text used in reporting
- `host` -- host name for the service endpoint
- `port` -- port number for the service endpoint
- `starttls` -- (optional) values `smtp` and `imap` are supported

There is an optional element `unsafe_validation` that when set to `true` will completely bypass the standard TLS validations of the CA, signature chain, and host name matching in the certificate. **If you are skipping these validations in production, you are usually making a very big mistake.**

Starttls is used when the initial endpoint connection starts as an unencrypted socket and then switches to a TLS encrypted socket after a "STARTTLS" command is issued. This is traditionally found with SMTP and IMAP servers. Modern use is typically only with SMTP MTA's that serve a dual function of receiving unauthenticated inbound messages and relaying outbound messages where the relay client must authenticate.

### Section: 'config'

These are general operating parameters for monitoring. 

- `warning_days` -- days before certificate expiration to start warning
- `critical_days` -- days before expiration to issue critical alerts

If a TLS certificate expires in `N` days, this is how it is classified for reporting:

- Critical: `N <= critical_days`
- Warning: `N <= warning_days`
- Good: `N > warning_days`

Additionally, any certificate that has not yet become valid -- has not reached the 'Not Before' date in the certificate -- is considered _Critical_ since it fails validation.

### Section 'notification'

This section describes the _who_ and _how_ for sending notifications.

#### Subsection 'source'

This contains details for whom the notifications come from and how they are delivered. Currently, only SMTP email is supported.

- `email` -- this is the notification type
- `email.address` -- the from-address for the email messages
- `email.from` -- the from-name for the email message (e.g., 'Certificate Watcher')
- `mailhost` -- defines how to send SMTP messages
- `mailhost.host` -- SMTP mail server (MTA) or relay
- `mailhost.port` -- (optional, default=25) mail server port
- `mailhost.user` -- (optional) MTA authentication user name
- `mailhost.password` -- (optional) authentication password for user

In deployments where internal clients are permitted to relay email without authentication, you will only need to set the `mailhost.host` parameter.

While the `email.from` value is optional, it allows for a well-formatted  
`From: from-name <from-addr>`  
header field that the recipients see in the outbound email message.

#### Subsection 'destinations'

This contains a list of entries that define to whom to deliver notifications. Each item in the list has these elements:

- `type` -- type of notification; currently only `email` is supported
- `address` -- the to-address for the email message (e.g., `bob@example.com`)
- `to` -- the to-name for the email message (e.g., 'Admin Bob')

While the `to` value is optional, it allows for a well-formatted  
`To: to-name <to-addr>`  
header field in the outbound email message. 

Each contact in the `destinations` list is sent a separate notification. In other words, separate emails addressed to one contact each are sent instead of a single message with a "To:" header that lists multiple contacts.


## Running

See the _Installation_ section for the two ways that you can run the tool either from a system-installed wheel or from a project source tree. For the examples in this section, I assume that you have installed the wheel on your system.

After configuration, this is basic usage to get a report for all certificates:
```sh
cert-watcher -c {/path/to/your-config.yaml}
```

You can filter the reporting to show only warning and critical certificates:
```sh
cert-watcher -c {your-config.yaml} -r critical -r warning
```

If you want to see the report without sending notifications, you can report to the console only:
```sh
cert-watcher -c {your-config.yaml} --console
```


Detailed help on all command line arguments:
```sh
cert-watcher --help
```


### Production Use

For production use, you can add one or more crontab entries to schedule the monitoring/reporting of your certificates.

This example shows a schedule where the status of all certificates is reported on Monday and only warning/critical certificates are reported the other days of the week. 

```crontab
# TLS Certificate Reporting; all certificates on Monday morning
5 0 * * 1 $HOME/.local/bin/cert-watcher -c /etc/cert-watcher/config.yaml

# TLS Certificate Reporting; crit/warn Tuesday through Sunday
5 0 * * 0,2-6 $HOME/.local/bin/cert-watcher -c /etc/cert-watcher/config.yaml -r critical -r warning
```
