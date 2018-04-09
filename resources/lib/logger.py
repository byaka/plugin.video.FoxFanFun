# -*- coding: utf-8 -*-
from resources.lib.functionsex import *

class RemoteLogger(object):
   def __init__(self, addr, app=None, cb=None):
      self.app=app or ''
      self.enabled=False
      if not addr: return
      try:
         s=getHtml2('http://%s/ping'%addr, silent=True, raiseErrors=True)
         assert s=='pong', 'Wrong answer "%s"'%s
      except Exception, e:
         print '!!! Remote-logger disabled:', e
         return
      self.enabled=True
      self.addr='http://%s/log/%s %%s/%%s'%(addr, self.app)
      self._addr=addr
      self._cb=cb

   def _log(self, type, args):
      caller=selfInfo(-4)
      caller.module=getScriptName(True, f=caller.module)
      caller.name='<%(module)s>.%(name)s()'%caller if caller.name!='<module>' else '<%s>'%caller.module
      caller='%(name)s:%(line)s'%caller
      data=[]
      for x in args:
         if not isString(x):
            try: x=str(x)
            except:
               try: x=repr(x)
               except:
                  try: x=reprEx(x)
                  except: x='<UNDUMPABLE>'
         data.append(x)
      data=' '.join(data)
      prefix='  '
      if type=='warn': prefix='? '
      if type=='err': prefix='!!'
      print '%s [%s %s] %s'%(prefix, self.app, caller, data)
      if isFunction(self._cb):
         try: self._cb(type, data)
         except: pass  # noqa
      if not self.enabled: return
      try:
         getHtml2(self.addr%(caller, type), type='post', data=data, silent=True, raiseErrors=True)
      except Exception, e:
         print '!!! Remote-logger error:', e

   def log(self, *args):
      self._log('log', args)

   def warn(self, *args):
      self._log('warn', args)

   def err(self, *args):
      self._log('err', args)
