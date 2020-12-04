#!/bin/sh
curl --tlsv1.3 --verbose --progress-bar --ssl-reqd --url $URL --output ~/$File
