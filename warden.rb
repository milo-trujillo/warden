#!/usr/bin/env ruby

require 'date'

LogFile = "/var/log/auth.log"
BlockCommand = "pfctl -t ssh_badlist -T add"

ThresholdAttempts = 10
ThresholdTime = 5
WhiteList = ["10.0.0."]

# Splits a log message in to the date (which is parsed), and the content
def splitDate(line)
	# Example: "Jun 27 15:03:16 "
	matches = /^(\w+ \d+ \d{2}:\d{2}:\d{2}) (.*)/.match(line)
	date = DateTime.parse(matches[1]).to_date
	return [date, matches[2]]
end

# Parses a message, identifies if it's an authentication failure and returns ip or nil
def parseMessage(message)
	match = /authentication error for [\S]+ from (\d+\.\d+\.\d+\.\d+)/.match(message)
	if( match != nil )
		return match[1]
	end
	match = /Invalid user [\S]+ from (\d+\.\d+\.\d+\.\d+)/.match(message)
	if( match != nil )
		return match[1]
	end
	match = /maximum authentication attempts exceeded for .* from (\d+\.\d+\.\d+\.\d+)/.match(message)
	if( match != nil )
		return match[1]
	end
	return nil
end

loglines = File.read(LogFile).split("\n")
now = DateTime.now.to_date
offenders = Hash.new(0)

for line in loglines
	date, msg = splitDate(line)
	age = (now - date).to_i
	if( age > ThresholdTime )
		next
	end
	ip = parseMessage(msg)
	if( ip != nil )
		for addr in WhiteList
			if( ip.start_with?(addr) )
				next
			end
		end
		offenders[ip] += 1
	end
end

offenders.each do |ip, offences|
	if( offences >= ThresholdAttempts )
		system("#{BlockCommand} #{ip}")
	end
end
