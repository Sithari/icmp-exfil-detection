# Copied and modified version of https://github.com/evernote/bro-scripts/blob/master/human/scripts/main.zeek

module human_readable;

export {
	global bytes_to_human_string: function(size: double, multiple: count &default=1000) : string;
	global interval_to_human_string: function(i: interval) : string;

}

function bytes_to_human_string(size: double, multiple: count &default=1000) : string {
	local suffixes: table[count] of vector of string = {
	[1000] = vector("KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"),
	[1024] = vector("KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"),
	};

	if (size < multiple)
		{
		return fmt("%.0f Bytes", size);
		}
	else
		{
		for (suffix in suffixes[multiple])
			{
			size = size / multiple;
			if (size < multiple)
				return fmt("%.2f %s", size, suffixes[multiple][suffix]);
			}
		}
}

function interval_to_human_string(i: interval) : string {
	local human_interval: string = " ";
	local total_seconds = double_to_count(interval_to_double(i));
	local seconds = total_seconds % 60;
	local minutes = total_seconds / 60 % 60;
	local hours = total_seconds / 60 / 60 % 60 %24;
	local days = total_seconds / 60 / 60 / 24;

	if (days > 0)
		{
		human_interval = fmt(" %d day", days);
			{
			if (days > 1) human_interval = string_cat(human_interval, "s");
			}
		}
	if (hours > 0)
		{
		human_interval = string_cat(human_interval, fmt(" %d hour", hours));
			{
			if (hours > 1) human_interval = string_cat(human_interval, "s");
			}
		}
	if (minutes > 0)
		{
		human_interval = string_cat(human_interval, fmt(" %d minute", minutes));
			{
			if (minutes > 1) human_interval = string_cat(human_interval, "s");
			}
		}
	if (seconds > 0)
		{
		human_interval = string_cat(human_interval, fmt(" %d second", seconds));
			{
			if (seconds > 1) human_interval = string_cat(human_interval, "s");
			}
		}
	
	return strip(human_interval);
}
