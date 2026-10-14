import re, subprocess, os, hashlib, sys, json

BASE='https://online.s-pankki.fi'
UA='@wearehackerone'

def raw(args, jar=None):
    cmd=['curl','-sk','-m','40','-A',UA]
    if jar:
        cmd+=['-b',jar,'-c',jar]
    r=subprocess.run(cmd+args,capture_output=True,text=True)
    return r

def curl(url, jar='cjL.txt', outfile=None, extra=None, method=None, data=None, headers=None):
    if not outfile:
        outfile='_t_'+hashlib.md5(url.encode()).hexdigest()[:10]+'.html'
    cmd=['curl','-sk','-m','40','-A',UA]
    if jar:
        cmd+=['-b',jar,'-c',jar]
    if method: cmd+=['-X',method]
    for k,v in (data or {}).items():
        cmd+=['--data-urlencode',f'{k}={v}']
    if headers:
        for k,v in headers.items(): cmd+=['-H',f'{k}: {v}']
    cmd+=['-D','_ph.txt','-o',outfile,url]
    if extra: cmd+=extra
    subprocess.run(cmd,capture_output=True,text=True)
    try: h=open('_ph.txt',errors='ignore').read()
    except Exception: h=''
    try: b=open(outfile,encoding='utf-8',errors='ignore').read()
    except Exception: b=''
    red=[l.strip() for l in h.splitlines() if l.lower().startswith('location:')]
    code=[l for l in h.splitlines() if 'HTTP/' in l][-1]
    return code,red,h,b

def login(jar='cjL.txt'):
    if os.path.exists(jar): os.remove(jar)
    code,red,h,b = curl(BASE+'/ebank/auth/initLogin.do?language=1', jar=jar, outfile='_l1.html')
    TOKEN=re.search(r'name="org\.apache\.struts\.taglib\.html\.TOKEN" value="([a-f0-9]{32})"', b).group(1)
    code,red,h,b = curl(BASE+'/ebank/auth/loginEbank.do', jar=jar, method='POST',
        data={'org.apache.struts.taglib.html.TOKEN':TOKEN,'language':'fi','startPage':'',
              'sloanCampaignCode':'','username':'12345678','password':'123456','btn_log_in':'Jatka'})
    # continuation (async login)
    for _ in range(5):
        code,red,h,b = curl(BASE+'/ebank/auth/initEbankSession.do', jar=jar, outfile='_l2.html')
        m=re.search(r'URL=([^"]+)"', b)
        if m and 'initEbankSession' not in m.group(1):
            break
    # follow to frontpage
    code,red,h,b = curl(BASE+'/ebank/menu/redirectByMenu.do?menuId=frontpage', jar=jar, outfile='_l3.html')
    # final home
    if red:
        loc=red[0].replace('Location: ','')
        code,red,h,b = curl(loc, jar=jar, outfile='_home.html')
    return code,red,b

def text(b, maxlen=600):
    t=re.sub(r'\s+',' ',re.sub(r'<script[\s\S]*?</script>|<style[\s\S]*?</style>|<[^>]+>',' ',b))
    return t[:maxlen]

def is_closed(b):
    return 'yhteys on suljettu' in b or 'yhteys on suljettu' in text(b,300)

if __name__=='__main__':
    code,red,b = login()
    print('LOGIN:', code, red, 'closed' if is_closed(b) else 'OK')
    t=text(b,300)
    print(t)
