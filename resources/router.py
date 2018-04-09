# -*- coding: utf-8 -*-
import xbmc, xbmcplugin, xbmcaddon, xbmcgui
from kodiswift import Plugin

from lib.functionsex import *
from lib.logger import RemoteLogger

from app import FoxFanFun

REMOTE_LOG=None
REMOTE_LOG='192.168.2.33:21001'

logger=RemoteLogger(REMOTE_LOG, 'KodiFFF')

class Router(object):

   def __init__(self, addonPath, app=None):
      self.plugin=Plugin()
      self.app=app or FoxFanFun(self.plugin, addonPath)
      self.loadMenu()
      # xbmc.executebuiltin('Container.SetViewMode(500)') # Вид "Эскизы".
      # xbmc.executebuiltin('Container.SetViewMode(512)') # Вид "Инфо-стена"

   def loadMenu(self):
      self.plugin.add_url_rule('/', self.menu_shows, 'menu_shows')
      self.plugin.add_url_rule('/watch/<showId>', self.menu_seasons, 'menu_seasons')
      self.plugin.add_url_rule('/watch/<showId>/<seasonId>', self.menu_episodes, 'menu_episodes')
      self.plugin.add_url_rule('/watch/<showId>/<seasonId>/<episodeId>', self.menu_watch, 'menu_watch')

   def menu_shows(self):
      tArr=self.app.listShow()
      tArr=sorted((v for v in tArr.itervalues()), key=lambda o: o.watched)
      res=[]
      self.plugin.set_content('tvshows')
      for o in reversed(tArr):
         res.append({
            'label': o.name,
            # 'path': self.plugin.url_for(self.menu_seasons, showId=o.showId),
            'path':'plugin://plugin.video.FoxFanFun/watch/%(showId)s'%o,
            'info_type':'video',
            'info':{
               'count':o.watched,
               'tvshowtitle': o.name,
               'mediatype':'tvshow',
            },
            'icon':o.icon,
            'thumbnail':o.cover,
            'properties':{
               'fanart_image':o.coverBig,
            },
         })
      return res

   def menu_seasons(self, showId):
      tArr=self.app.listSeason(showId)
      tArr=sorted((v for v in tArr.itervalues()), key=lambda o: o.sorter)
      res=[]
      for o in reversed(tArr):
         res.append({
            'label': o.name,
            'path':'plugin://plugin.video.FoxFanFun/watch/%(showId)s/%(seasonId)s'%o,
            'info_type':'video',
            'info':{
               'count':o.sorter,
               'tvshowtitle': self.app.data[o.showId].name,
               'mediatype':'season',
               'season':int(o.seasonId),
            },
         })
      return res

   def menu_episodes(self, showId, seasonId):
      tArr=self.app.listEpisode(showId, seasonId)
      tArr=sorted((v for v in tArr.itervalues()), key=lambda o: o.sorter)
      res=[]
      self.plugin.set_content('episodes')
      for o in tArr:
         res.append({
            'label': o.name,
            'path':'plugin://plugin.video.FoxFanFun/watch/%(showId)s/%(seasonId)s/%(episodeId)s'%o,
            # 'info_type':'video',
            'info':{
               'count':o.sorter,
               'tvshowtitle':self.app.data[o.showId].name,
               'title': o.name,
               'mediatype':'episode',
               'season':int(o.seasonId),
               'episode':int(o.episodeId),
               'plot':o.descr,
               'plotoutline':o.descr,
            },
            'thumbnail':o.coverBig,
            'properties':{
               'fanart_image':o.coverBig,
            },
            'is_playable':True,
         })
      res=self.plugin.add_to_playlist(res, playlist='video')
      return res

   def menu_watch(self, showId, seasonId, episodeId):
      o=self.app.watch(showId, seasonId, episodeId)
      if not o:
         return []
      elif o.get('error'):
         return [{'label':o.error, 'path':None}]
      return self.plugin.set_resolved_url(o.file)
