# -*- coding: utf-8 -*-
import sys, os
import requests

from lib.functionsex import *
from lib.domer import DOM as htmlParse
from lib.logger import RemoteLogger
try:
   from cStringIO import StringIO
except ImportError:
   from StringIO import StringIO

__VERSION__=0.35

REMOTE_LOG=None
REMOTE_LOG='192.168.2.33:21001'

logger=RemoteLogger(REMOTE_LOG, 'KodiFFF')

IMAGE_COMPRESSION_ENABLED=False
try:
   from PIL import Image
   IMAGE_COMPRESSION_ENABLED=True
except ImportError: pass
if not IMAGE_COMPRESSION_ENABLED:
   logger.warn('Image compression disabled')

class FoxFanFun(object):

   def __init__(self, plugin, addonPath):
      self.version=MagicDict({'db':__VERSION__})
      self.plugin=plugin
      self.path=MagicDict({
         'tmp':os.path.join(addonPath, 'resources', 'tmp')+'/',
         # special://thumbnails
         'image':os.path.join(addonPath, 'resources', 'img')+'/',
         'cover':os.path.join(addonPath, 'resources', 'cached', 'cover')+'/',
      })
      logger._cb=lambda t, s: self.notify(s, t)
      mytime=getms(True)
      self.data=self.plugin.get_storage('data')
      self.special=self.plugin.get_storage('special')
      if 'lastUpdate' not in self.special:
         self.special['lastUpdate']={'showList':0}
      self.temp=self.plugin.get_storage('temp', ttl=30)
      self._checkDB()
      logger.log('DB inited at %.1fsec'%((getms(True)-mytime)/1000.0))

   def _checkDB(self):
      try: v=numEx(self.special.get('dbVersion'), forceFloat=True)
      except: v=0  # noqa
      logger.log('Checking DB (version %s)'%v)
      if v<0.21:
         logger.warn('Appling DB patches from version 0.21')
         # added 'watched' counter
         def tFunc_watched(o):
            if 'watched' not in o: o['watched']=0
         tArr=[self.data]
         while len(tArr):
            for o in tArr.pop().itervalues():
               if 'watched' not in o: o['watched']=0
               if 'lastWatched' not in o: o['lastWatched']=0
               if 'data' in o:
                  tArr.append(o.data)
      if v<0.34:
         logger.warn('Appling DB patches from version 0.34')
         # added 'alias' field to shows
         for o in self.data.itervalues():
            if 'alias' not in o: o['alias']=[]
         self.special['needUpdate_showList']=True
      # saving
      self.special['dbVersion']=self.version.db
      self.data.sync()
      self.special.sync()

   def notify(msg, errorOrType=None):
      if errorOrType is True: errorOrType='err'
      if isString(errorOrType):
         errorOrType=errorOrType.lower()
      typeMap={
         'err':('', '', 'icon_error.png', 10000),
         'warn':('', '', 'icon_warn.png', 10000),
         'ok':('', '', 'icon_ok.png', 3000),
      }
      o=typeMap.get(errorOrType, typeMap['ok'])
      s='%s Fox-Fan-Fun %s'%(o[0], o[1])
      self.plugin.notify(msg, title=s, image=(self.path.image+o[2] if o[2] else None), delay=o[3])

   def ua(self):
      return 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36'

   def _auth(self):
      self._loadUrl('fox-fan.ru', type='head', noCookie=True)

   def _loadUrl(self, url, data=None, type=None, noCookie=False):
      if not url.startswith('http'): url='http://'+url
      if not type:
         type='get' if not data else 'post'
      r=getHtml2(url, type=type, followRedirect=True,
         headers={'User-Agent':self.ua()},
         cookies=None if noCookie else self.cookie(),
         data=data,
         proxie=None, timeout=15,
         returnOnlyData=False, tryForceEncoding=False, forceEncoding=False,
         silent=True, raiseErrors=True)
      if r.cookies and self.temp.get('cookie')!=r.cookies:
         self.temp['cookie']=r.cookies
         logger.log('Cookies changeed to', self.temp['cookie'])
      return r

   def load(self, url, data=None):
      r=self._loadUrl(url, data=data)
      # checking here
      pass
      r.data=clearTypography(r.data)
      return r.data

   def cookie(self, plain=False):
      if not self.temp.get('cookie'): self._auth()
      s=self.temp['cookie']
      if plain:
         s=urllib.urlencode(s)
      return s

   def _checkAuth(self):
      pass

   def _checkNeedUpdate(self, val, ttl):
      if not val: return True
      if val is True: return False
      if isString(ttl):
         if ttl[0]=='d': ttl=86400*numEx(ttl[1:])
         elif ttl[0]=='h': ttl=3600*numEx(ttl[1:])
         elif ttl[0]=='m': ttl=60*numEx(ttl[1:])
         else: ttl=numEx(ttl)
      if not isNum(ttl):
         logger.err('Incorrect TTL value', ttl, type(ttl))
         return False
      diff=getms(False)-val
      return diff>ttl

   def _parseHtml(self, url, data):
      mytime=getms(True)
      res=htmlParse(data)
      logger.log('Html "%s"(%.1fkb) parsed at %.1fsec'%(url, len(data)/1000.0, (getms(True)-mytime)/1000.0))
      return res

   def _loadImage(self, url, path, allowCompression=True):
      # ? можно еще сделать ttl на основе time-modified через os.path.getmtime()
      if os.path.isfile(path): return True
      logger.log('Downloading new image', url)
      try:
         r=requests.get(url, allow_redirects=True, headers={'User-Agent':self.ua()}, cookies=self.cookie())
         if IMAGE_COMPRESSION_ENABLED and allowCompression:
            # logger.log('Compressing new image', url)
            img=Image.open(StringIO(r.content))
            img.save(path, "JPEG", quality=(allowCompression if isInt(allowCompression) else 70))
         else:
            with open(path, 'wb') as f: f.write(r.content)
      except Exception, e:
         logger.err('Cant load image', url, e)
         return False
      return True

   def _prepShowUrl(self, showId):
      urlArr=urlparse(self.data[showId].url)
      urlArr=dict((k, getattr(urlArr, k)) for k in ('netloc', 'scheme'))
      return urlArr

   def _url2showId(self, url):
      showId=urlsplit(url).netloc.lower().replace('.', '-')
      return showId

   def listShow(self, force=None):
      if force is True or force=='update': lastUpdate=False
      elif force=='cache': lastUpdate=True
      else:
         lastUpdate=self.special['lastUpdate'].get('showList')
      if not len(self.data) and force!='cache': lastUpdate=False
      #
      if self.special.get('needUpdate_showList'):
         del self.special['needUpdate_showList']
         lastUpdate=False
      #
      if self._checkNeedUpdate(lastUpdate, 'd7') is True:
         logger.log('Time to update')
         showListUrl='fox-fan.ru'
         data=self.load(showListUrl)
         html=self._parseHtml(showListUrl, data)
         tArr1=html.get('.menuList')+html.get('.menuList1')+html.get('.menuList2')+html.get('.menuList3')
         notEmpty=False
         for o in tArr1:
            try:
               tArr=o.getOne('ul').getOne('li').get('li')
            except: continue  # noqa
            for oo in tArr:
               oo=oo.getOne('a')
               if not oo: continue
               try:
                  showId=self._url2showId(oo.attr['href'])
                  name=oo.content
                  url=oo.attr['href'].lower()
               except Exception, e:
                  logger.warn('Cant parse item', oo.source, e)
                  continue
               # check in cache
               if showId not in self.data:
                  self.data[showId]=MagicDict({'data':{}, 'alias':[], 'watched':0, 'lastWatched':0})
               # updating info
               icon=self.path.cover+'%s__icon.png'%showId
               self._loadImage(rebuildURL(url, {'path':'/images/logo.png'}), icon, allowCompression=False)
               cover=''
               coverBig=self.path.cover+'%s__coverBig.jpg'%showId
               self.data[showId].update({
                  'name':name,
                  'url':url,
                  'showId':showId,
                  'icon':icon,
                  'cover':coverBig or cover,
                  'coverBig':coverBig or cover,
               })
               notEmpty=True
         #
         if notEmpty:
            self.special['lastUpdate']['showList']=getms(False)
            self.findShowCovers(html, showListUrl)
      return self.data

   def findShowCovers(self, html=None, htmlFromUrl='fox-fan.ru'):
      tArr1={htmlFromUrl:html}
      if not html:
         data=self.load(htmlFromUrl)
         html=self._parseHtml(htmlFromUrl, data)
         tArr1[htmlFromUrl]=html
      #
      try:
         for o in html.getOne('#top').get('div'):
            if not o.id or not o.id.lower().startswith('logo'): continue
            try:
               s=o.getOne('a').attr['href']
               s=urlsplit(s).netloc
               if s in tArr1: continue
               tArr1[s]=None
            except: continue  # noqa
      except Exception, e:
         logger.warn('Cant extract another main pages', e)
      for url, html in tArr1.iteritems():
         if not html:
            data=self.load(url)
            html=self._parseHtml(url, data)
         try:
            tArr=html.getOne('.jimgMenu_2').getOne('ul').get('li')
         except Exception, e:
            logger.warn('Cant extract covers from', url, e)
            continue
         for o in tArr:
            try:
               alias=o.id+''
               showId=self._url2showId(o.getOne('a').attr['href'])
               if showId not in self.data:
                  logger.warn('Finded cover for unknown showId', showId, url)
                  continue
               if alias not in self.data[showId].alias:
                  self.data[showId].alias.append(alias)
               self._loadImage('http://%s/images/%s.jpg'%(url, alias), self.path.cover+'%s__coverBig.jpg'%showId, allowCompression=90)
            except Exception, e:
               logger.warn('Error when extracting cover from', url, e)
               continue

   def listSeason(self, showId, force=None):
      if showId not in self.data:
         logger.err('Unknown showId', showId)
         return {}
      if force is True or force=='update': lastUpdate=False
      elif force=='cache': lastUpdate=True
      else:
         lastUpdate=self.data[showId].get('lastUpdate')
      if not len(self.data[showId].data) and force!='cache': lastUpdate=False
      #! здесь нужно динамически выбирать TTL если пользователь запрашивал список серий в последнем сезоне
      if self._checkNeedUpdate(lastUpdate, 'd5') is True:
         logger.log('Time to update', showId)
         data=self.load(self.data[showId].url)
         html=self._parseHtml(self.data[showId].url, data)
         # selecting compatible parser
         parsers=(
            (lambda:html.getOne('.numberSeason'), '_listSeason_normal'),
            (lambda:html.getOne('table.seasons_block') and html.getOne('#otherSeasons'), '_listSeason_badTable'),
         )
         for cond, p in parsers:
            try:
               assert cond(), 'skip'
            except: continue  # noqa
            try:
               if getattr(self, p)(showId, html): break
            except Exception:
               logger.err('Parser "%s" throw'%p, getErrorInfo())
               continue
         else:
            logger.err('No compatible parser for', showId)
      return self.data[showId].data

   def _processSeason(self, showId, seasonId, seasonUrl, checkEpsOnPage):
      seasonId=strEx(seasonId)
      url=rebuildURL(seasonUrl, {'query':{'id':seasonId}})
      # check in cache
      if seasonId not in self.data[showId].data:
         self.data[showId].data[seasonId]=MagicDict({'data':{}, 'watched':0, 'lastWatched':0})
      # updating info
      self.data[showId].data[seasonId].update({
         'name':u'Сезон %s'%(seasonId),
         'showId':showId,
         'seasonId':seasonId,
         'sorter':int(seasonId),
         'url':url,
      })
      # check on page
      if isFunction(checkEpsOnPage):
         epsHtml=checkEpsOnPage(showId, seasonId, url)
      else: epsHtml=checkEpsOnPage
      if epsHtml:
         # season on page, parsing episodes
         logger.log('Parsing included season', showId, seasonId)
         self.listEpisode(showId, seasonId, html=epsHtml)
      return True

   def _listSeason_normal(self, showId, html):
      # парсинг нормальной верстки, например для симпсонов
      urlArr=self._prepShowUrl(showId)
      try:
         seasonsOnPage=[o.getOne('a') for o in html.get('.numberSeason')]
         seasonUrl=rebuildURL(seasonsOnPage[0].attr['href'], urlArr)
         maxSeason=parse_qs(urlparse(seasonUrl).query)['id'][0]
         maxSeason=int(maxSeason)
         seasonsOnPage=dict((rebuildURL(o.attr['href'], urlArr), o.parent.parent.next()) for o in seasonsOnPage if o.attr.get('href', '#')!='#')
      except Exception, e:
         logger.err('Cant extract max season', e)
         return False
      notEmpty=False
      for seasonId in xrange(maxSeason, 0, -1):
         notEmpty=self._processSeason(showId, seasonId, seasonUrl, lambda _1, _2, url:seasonsOnPage.get(url)) or notEmpty
      if notEmpty:
         self.data[showId].lastUpdate=getms(False)
      return notEmpty

   def _listSeason_badTable(self, showId, html):
      # парсинг табличной верстки без идентификаторов, например для гриффинов
      urlArr=self._prepShowUrl(showId)
      try:
         seasonsOnPage=html.get('a.link_25')
         seasonUrl=rebuildURL(seasonsOnPage[0].attr['href'], urlArr)
         maxSeason=parse_qs(urlparse(seasonUrl).query)['id'][0]
         maxSeason=int(maxSeason)
         seasonsOnPage=dict((rebuildURL(o.attr['href'], urlArr), o.parent.parent.parent.next()) for o in seasonsOnPage if o.attr.get('href', '#')!='#')
      except Exception, e:
         logger.err('Cant extract max season', e)
         return False
      notEmpty=False
      for seasonId in xrange(maxSeason, 0, -1):
         notEmpty=self._processSeason(showId, seasonId, seasonUrl, lambda _1, _2, url:seasonsOnPage.get(url)) or notEmpty
      if notEmpty:
         self.data[showId].lastUpdate=getms(False)
      return notEmpty

   def listEpisode(self, showId, seasonId, html=None, force=None):
      if showId not in self.data:
         logger.err('Unknown showId', showId)
         return {}
      if seasonId not in self.data[showId].data:
         logger.err('Unknown seasonId', showId, seasonId)
         return {}
      if not html:
         if force is True or force=='update': lastUpdate=False
         elif force=='cache': lastUpdate=True
         else:
            lastUpdate=self.data[showId].data[seasonId].get('lastUpdate')
         if not len(self.data[showId].data[seasonId].data) and force!='cache': lastUpdate=False
         ttl='d30'
         if self.data[showId].data[seasonId].sorter==len(self.data[showId].data):
            ttl='h23'  # если это последний сезон, обновляем список серий ежедневно
         if self._checkNeedUpdate(lastUpdate, ttl) is True:
            logger.log('Time to update', showId, seasonId)
            data=self.load(self.data[showId].data[seasonId].url)
            html=self._parseHtml(self.data[showId].data[seasonId].url, data)
      if html:
         # selecting compatible parser
         parsers=(
            (lambda:html.id=='descrSeason' and html.getOne('.smallSeason'), '_listEpisode_gallery'),
            (lambda:html.tag.lower()=='tr', '_listEpisode_gallery_badTable'),
            (lambda:html.getOne('table.seasons_block'), '_listEpisode_list_badTable'),
            (lambda:html.getOne('#descrSeason').getOne('table'), '_listEpisode_list'),
         )
         for cond, p in parsers:
            try:
               assert cond(), 'skip'
            except: continue  # noqa
            try:
               if getattr(self, p)(showId, seasonId, html): break
            except Exception:
               logger.err('Parser "%s" throw'%p, getErrorInfo())
               continue
         else:
            logger.err('No compatible parser for', showId, seasonId)
      return self.data[showId].data[seasonId].data

   def _processEpisode(self, showId, seasonId, episodeId, url, title, descr, coverUrl, tryExtractBigCover=True):
      cover=self.path.cover+'%s__%s%s__cover.jpg'%(showId, seasonId, episodeId)
      coverBig=''
      if coverUrl and tryExtractBigCover:
         coverBigUrl=coverUrl.replace('%s%s.'%(seasonId, episodeId), '%s%s_big.'%(seasonId, episodeId))
         coverBig=self.path.cover+'%s__%s%s__coverBig.jpg'%(showId, seasonId, episodeId)
         self._loadImage(coverBigUrl, coverBig)
      else:
         self._loadImage(coverUrl, cover)
      # check in cache
      if episodeId not in self.data[showId].data[seasonId].data:
         self.data[showId].data[seasonId].data[episodeId]=MagicDict({'watched':0, 'lastWatched':0})
      # updating info
      self.data[showId].data[seasonId].data[episodeId].update({
         'name':title.strip(),
         'showId':showId,
         'seasonId':seasonId,
         'episodeId':episodeId,
         'sorter':int(episodeId),
         'url':url,
         'cover':coverBig or cover,
         'coverBig':coverBig or cover,
         'descr':descr.strip(),
         'lastUpdate':getms(False),
      })
      return True

   def _url2episodeId(self, url, showId, seasonId):
      try:
         episodeId=parse_qs(urlparse(url).query)['id'][0]
         _, episodeId=episodeId.split(seasonId, 1)
         return episodeId
      except Exception, e:
         logger.warn('Cant extract episodeId from url', showId, seasonId, url, e)
         return False

   def _listEpisode_gallery(self, showId, seasonId, html):
      msgFix=' (CalledDirectly)' if isArray(html) else ''
      try:
         if isArray(html): tArr1=html
         else:
            tArr1=html.get('.smallSeason')
         assert tArr1, 'empty'
      except Exception, e:
         logger.err('Cant extract episodes%s'%msgFix, showId, seasonId, e)
         return False
      urlArr=self._prepShowUrl(showId)
      notEmpty=False
      for o in tArr1:
         try:
            url=o.getOne('a').attr.get('href')
            assert url, 'empty'
         except:  # noqa
            logger.warn('Cant extract url, skipping%s'%msgFix, showId, seasonId)
            continue
         episodeId=self._url2episodeId(url, showId, seasonId)
         if not episodeId: continue
         url=rebuildURL(url, urlArr)
         coverUrl=''
         for q in ('.title_1', '.title_1_other', '.title_2', '.title_2_other', '.title_3', '.title_3_other'):
            try:
               coverUrl=o.getOne(q).getOne('img').attr['src']
               assert coverUrl, 'empty'
               coverUrl=rebuildURL(coverUrl, urlArr)
            except: continue  # noqa
            break
         o=o.getOne('em')
         o=o.getOne('h2') or o.getOne('font.link_16')
         title=o.content
         descr=str(o.next())
         #
         notEmpty=self._processEpisode(showId, seasonId, episodeId, url, title, descr, coverUrl) or notEmpty
      #
      if notEmpty:
         self.data[showId].data[seasonId].lastUpdate=getms(False)
      return notEmpty

   def _listEpisode_gallery_badTable(self, showId, seasonId, html):
      try:
         tArr1=[]
         while True:
            if not html or not html.tag or html.tag.lower()!='tr': break
            tArr=html.get('td')
            if len(tArr)==1 and tArr[0].getOne('a.link_25'): break
            tArr1+=tArr
            html=html.next()
         assert tArr1, 'empty'
      except Exception, e:
         logger.err('Cant extract episodes', showId, seasonId, e)
         return False
      return self._listEpisode_gallery(showId, seasonId, tArr1)

   def _listEpisode_list(self, showId, seasonId, html):
      msgFix=' (CalledDirectly)' if isArray(html) else ''
      try:
         if isArray(html): tArr1=html
         else:
            tArr1=html.getOne('#descrSeason').getOne('table').get('tr')
         assert tArr1, 'empty'
      except Exception, e:
         logger.err('Cant extract episodes%s'%msgFix, showId, seasonId, e)
         return False
      if len(tArr1)%2:
         logger.warn('Items length not multiple by two%s'%msgFix, showId, seasonId)
      tArr1=arrSplit(tArr1)
      urlArr=self._prepShowUrl(showId)
      notEmpty=False
      for o1, o2 in tArr1:
         try:
            url=o1.getOne('a').attr.get('href')
            assert url, 'empty'
         except:  # noqa
            logger.warn('Cant extract url, skipping%s'%msgFix, showId, seasonId)
            continue
         episodeId=self._url2episodeId(url, showId, seasonId)
         if not episodeId: continue
         url=rebuildURL(url, urlArr)
         coverUrl=o1.getOne('img').attr.get('src')
         coverUrl=rebuildURL(coverUrl, urlArr)
         title=o1.getOne('h2').getOne('a').content
         descr=o2.getOne('td').content
         #
         notEmpty=self._processEpisode(showId, seasonId, episodeId, url, title, descr, coverUrl) or notEmpty
      #
      if notEmpty:
         self.data[showId].data[seasonId].lastUpdate=getms(False)
      return notEmpty

   def _listEpisode_list_badTable(self, showId, seasonId, html):
      try:
         tArr1=html.getOne('table.seasons_block').get('tr')[2:-2]
         assert tArr1, 'empty'
      except Exception, e:
         logger.err('Cant extract episodes', showId, seasonId, e)
         return False
      return self._listEpisode_list(showId, seasonId, tArr1)

   def watch(self, showId, seasonId, episodeId, voiceId=None):
      if showId not in self.data:
         logger.err('Unknown showId', showId)
         return MagicDict({})
      if seasonId not in self.data[showId].data:
         logger.err('Unknown seasonId', showId, seasonId)
         return MagicDict({})
      if episodeId not in self.data[showId].data[seasonId].data:
         logger.err('Unknown episodeId', showId, seasonId, episodeId)
         return MagicDict({})
      url=self.data[showId].data[seasonId].data[episodeId].url
      if voiceId:
         voiceId=strEx(voiceId)
         url=rebuildURL(url, {'query':{'voice':voiceId}})
      data=self.load(url)
      html=self._parseHtml(url, data)
      # extracting voice-tracks
      voiceMap={}
      voiceNow=None
      try:
         tArr1=html.getOne('#centerSeries').getOne('#voice').getOne('ul').get('li')
         for o in tArr1:
            isNow='voiceOn' in o.classes
            for oo in o.get('a'):
               try:
                  vId=parse_qs(urlparse(oo.attr['href']).query)['voice'][0]
                  vName=oo.content
                  if o.id=='captionsrusAll': vName=u'Субтитры '+vName
                  voiceMap[vId]=vName
                  if isNow: voiceNow=vId
               except Exception:
                  logger.warn('Cant parce voice-track\n', url, oo.source)
      except Exception:
         logger.err('Cant extract voice-tracks', url, getErrorInfo())
      if voiceId and voiceId!=voiceNow:
         logger.err('Cant find selected voice track', voiceId, voiceNow, url)
      # extracting video link
      if 'new Playerjs({' not in data:
         logger.err('Url for video not founded', showId, seasonId, episodeId)
         fileWrite(self.path.tmp+'%s__%s%s.html'%(showId, seasonId, episodeId), strUniDecode(data))
         return MagicDict({'error': 'Url for video not founded, page dumped'})
      o=strGet(data, 'new Playerjs({', '})')
      o=strGet(o, "file:'", "'")
      fileUrl=o+'|'+urllib.urlencode({
         'Cookie':self.cookie(True),
         'User-Agent':self.ua(),
         'Referer':url,
      })
      # fileWrite(self.path.tmp+'%s__%s%s.txt'%(showId, seasonId, episodeId), strUniDecode(fileUrl))
      self.data[showId].data[seasonId].data[episodeId].voiceMap=voiceMap
      res=MagicDict(dict(self.data[showId].data[seasonId].data[episodeId]))
      res.file=fileUrl
      res.voiceNow=voiceNow
      # print_r(res)
      # updating watch-counters
      self.data[showId].watched+=1
      self.data[showId].lastWatched=getms(False)
      self.data[showId].data[seasonId].watched+=1
      self.data[showId].data[seasonId].lastWatched=getms(False)
      self.data[showId].data[seasonId].data[episodeId].watched+=1
      self.data[showId].data[seasonId].data[episodeId].lastWatched=getms(False)
      return res
