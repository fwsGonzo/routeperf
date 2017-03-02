#!/bin/bash
brctl delif bridge43 tap1
brctl addif bridge44 tap1
ifconfig tap1 up

