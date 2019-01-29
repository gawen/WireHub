#!/bin/bash

NAME=test

rm -f /public.wh

echo "name $NAME" >> /public.wh
echo "subnet 10.0.42.1/24" >> /public.wh
echo "workbit 8" >> /public.wh
echo "boot P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w bootstrap.wirehub.io" >> /public.wh

CWD="$(dirname "$0")"
KPATH="$CWD/keys"

rm -f $KPATH/*.{sk,k}
mkdir -p $KPATH

for i in {1..9}
do
    echo "generating key $i..."
    wh genkey /public.wh | tee $KPATH/$i.sk | wh pubkey > $KPATH/$i.k
    echo "trust $i.$NAME `cat $KPATH/$i.k`" >> /public.wh
done

echo "###"
cat /public.wh | tee > $KPATH/config
