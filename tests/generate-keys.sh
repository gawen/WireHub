#!/bin/bash

NAME=test

wh clearconf $NAME
wh set $NAME workbit 8 subnet 10.0.42.1/24
wh set $NAME name bootstrap peer P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w untrusted bootstrap yes endpoint bootstrap.wirehub.io

CWD="$(dirname "$0")"
KPATH="$CWD/keys"

rm -f $KPATH/*.{sk,k}
mkdir -p $KPATH

for i in {1..9}
do
    echo "generating key $i..."
    wh genkey $NAME | tee $KPATH/$i.sk | wh pubkey > $KPATH/$i.k
    wh set $NAME name $i.$NAME ip 10.0.42.$i peer `cat $KPATH/$i.k`
done

wh showconf $NAME > $KPATH/config

