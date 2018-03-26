# -*- coding: utf-8 -*-
import sys, os, traceback
import xbmcaddon
from kodiswift import Plugin

from resources.lib.functionsex import *
from resources.lib.logger import RemoteLogger
from resources.router import Router

# Plugin().notify('Test msg here', delay=10000)

_ADDON_NAME='plugin.video.FoxFanFun'
_addon=xbmcaddon.Addon(id=_ADDON_NAME)
try: _addon_id=int(sys.argv[1])
except ValueError: _addon_id=0
_addon_url=sys.argv[0]
_addon_path=_addon.getAddonInfo('path').decode('utf-8')
if _addon_path.startswith('special://'):
   _addon_path=getScriptPath(f=__file__)

REMOTE_LOG=None
REMOTE_LOG='192.168.2.33:21001'

logger=RemoteLogger(REMOTE_LOG, 'KodiFFF')

def handleError(*err):
   if issubclass(err[0], KeyboardInterrupt):
      return sys.__excepthook__(*err)
   err=''.join(traceback.format_exception(*err))
   logger.err(err)

sys.excepthook=handleError

logger.log('Started..')
logger.log('Path:', _addon_path)
logger.log('Url:', _addon_url)

app=Router(_addon_path)

if __name__ == '__main__':
   app.plugin.run()
else:
   plugin=app.plugin
