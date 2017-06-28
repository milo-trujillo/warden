# Warden

Anyone that's run a server with ssh open to the Internet, and has looked at their logs, knows the Internet is plagued with infected machines trying to break in to yours.

This is a trivial script that reads the ssh log file and blocks offending IP addresses. Thresholds for what constitutes "offensive enough" are configurable. It also includes a whitelist, so you can be sure to never lock yourself out.

## Installation

Add a cronjob to a priviledged user that can read /var/log/auth.log and add new firewall rules (probably root) as follows:

     */15   *   *   *   *   /path/to/your/warden.rb

Warden will now read the ssh log file every 15 minutes and ban appropriate users.

## Default Configuration

By default, Warden assumes you're using [pf](https://www.freebsd.org/doc/handbook/firewalls-pf.html), and have a block list called `ssh_badlist`. Both of these are trivial to change - just swap out the BlockCommand at the top of the file.

Warden will only look at failed logins from the last five days, and block anyone who has failed to log in ten or more times in that period.

## Why doesn't it have [insert arbitrary feature]?

There are many [more sophisticated solutions to this problem](https://en.wikipedia.org/wiki/Fail2ban). I wanted to build one with absolutely minimal dependencies, with exactly what I needed in it.
