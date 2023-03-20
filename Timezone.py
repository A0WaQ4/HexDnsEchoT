
import pytz
import datetime
import time

print(len(pytz.all_timezones))
for timezone in pytz.all_timezones:
    print(timezone)
    tz=pytz.timezone(timezone)
    t=datetime.datetime.fromtimestamp(int(time.time()),tz).strftime('%Y-%m-%d %H:%M:%S %Z%z')
    print(t)
