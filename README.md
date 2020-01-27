# PoC for the SWAPGS attack ([CVE-2019-1125](https://nvd.nist.gov/vuln/detail/CVE-2019-1125))

This repository holds the sources for the SWAPGS attack PoC publicly shown at Black Hat USA, 2019.

## Contents

* leakgsbkva - variant 1 (look for random values in kernel memory; limited to PE kernel image header)
* leakgsbkvat - variant 2 (extract random values from kernel memory; limited to PE kernel image header)
* whitepaper
* Black Hat USA 2019 presentation

## Prerequisites

1. Visual Studio 2015
2. Unpatched Windows x64 (7 or newer)

## Authors

* Andrei Vlad LUȚAȘ
* Dan Horea LUȚAȘ

## Additional resources

[Video Recording of presentation at Black Hat USA, 2019](https://www.youtube.com/watch?v=uBPry7jcfBE)
