#!/usr/bin/python3
# -*- coding: utf-8 -*-
import colorama
from colorama import Fore, Back
import shlex
import signal
import readline
import os, sys

folder = os.path.dirname(os.path.abspath(__file__)) + "/lib/"
sys.path.append(folder)

import lan_vulner_cmd
import time


def tokenize(string):
    """
    	to get a well formed command+args
    """
    return shlex.split(string)

def shell_loop():
    # auto-completion
    readline.set_completer(lan_vulner_cmd.completer)
    readline.parse_and_bind('tab: complete')

    c = True
    while c:
        # display a command prompt
        cmd = input(Back.WHITE+Fore.RED+' LAN vulner (help)> '+Back.RESET+Fore.CYAN+' ')

    	# tokenize the command input
        cmd_tokens = tokenize(cmd)

    	# execute the command
        lan_vulner_cmd.execute(cmd_tokens)


def closeProgram(signal, frame):
    sys.exit(1)

def main():
    signal.signal(signal.SIGINT, closeProgram) # close program with Ctrl+C

    shell_loop()

if __name__ == '__main__':
    main()
