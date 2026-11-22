#!/bin/sh
# Northfire Services test: stands in for sendmail and keeps each message in /work/test/mail.log,
# so the tests can read what services emailed. Built by Kyle Bargman
{ echo "----- MAIL"; cat; } >> /work/test/mail.log
