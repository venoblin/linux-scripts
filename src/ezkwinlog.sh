#!/bin/zsh
#starts kwin's logger for debugging purposes

journalctl -f QT_CATEGORY=js QT_CATEGORY=kwin_scripting
