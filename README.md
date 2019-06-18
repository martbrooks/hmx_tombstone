# The antibodyMX and hardenedMX tombstone

## Preamble

This is the final resting place of two junk mail filtering projects that I ran,
with significant help from others, for very nearly two decades.  At its peak,
the service filtered mail for just shy of 500 domains, processing upwards of
100,000 messages per day.  In very nearly two decades of operation, we had no
unplanned downtime and not one single service affecting outage.  We had
outages, just not ones that the customers ever got to see.  Slightly proud of
that.

These days, the email filtering you get with your "free" email provider, or
that of your corporate email provider, is good enough for most people.  As such
it's essentially more luck than judgement if you can keep a small independent
filtering service going.  I have been relying on a couple of niche customers to
keep the service profitable but, as of July 31st 2019, I have the choice of
either committing to three more years, or calling it a day.  So, uum, bye!

## Contents

One thing you'll notice almost immediately is that there's not a lot in this
repo; a PostgreSQL schema dump and an exim4 configuration file.  It's not a
lot, but they do form the basis of a very configurable mail system. Whitelists
(many types), blacklists (many types), greylists, routed domains, virtual
domains, redirects: it's all in there.

Most obviously missing are a bunch of helper scripts to deal with things like
geoip and ASN lookups,  I'll get round to adding them at some point.
