# -*- coding: UTF-8 -*-
#!/usr/bin/python

import requests
import time
import json
from base64 import b64encode
import urllib3
urllib3.disable_warnings()


from Time import TimeAligner

from Cryptoo import rsa_publickey,pkcs1v15_encrypt


intBase = int

class AccountWebLogin():
    req = requests.session()
    
    phone_guard_number = ''
    captchagid = '-1'
    aligned_time = None
    password_encrypt = None
    timestamp = None
    saved_cookie = None
    sessionid = None
    dologin_flag = True

    need_phone_guard_number_flag = False
    
    need_emailauth_number_flag = False
    
    captcha_text = ''
    emailauth = ''
    
    too_many_defeats = False
    
    time_offset = 0
    
    get_sessionid_retry_num = 3
    get_rsa_retry_num = 3
    dologin_retry_num = 5
        
    defeat_flag = False

    username = ''
    password = ''
    shared_secret = ''

    header = {
            'Host': 'store.steampowered.com',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            }    
    def __init__(self,username,password,aligned_time):
        self.username = username
        self.password = password
        self.aligned_time = aligned_time

    def get_sessionid(self):
        print('getting sessionid...')
        try:
            self.req.get(url="https://store.steampowered.com/login/",headers=self.header)
            self.sessionid = self.req.cookies.get_dict().get('sessionid')
#            print('\nsessionid\n',self.sessionid)
        except:
#            print('\nconnection error,wait and retry\n')
            time.sleep(1)
            self.get_sessionid_retry_num -= 1
            if self.get_sessionid_retry_num != 0:
                self.get_sessionid()
            else:
#                print('get sessionid defeat')
                self.defeat_flag = True

    def getrsa(self):
        print('get rsa key...')
        if self.defeat_flag == False:
            getrsa_post_data = {
                            'donotcache':str(int(time.time()*1000)),
                            'username':self.username
                            }
            try:                
                getrsa_response= self.req.post(url='https://store.steampowered.com/login/getrsakey/',
                                          headers=self.header,data=getrsa_post_data,timeout = 12)
                if getrsa_response.status_code == 200:  
                    print('get rsa key success')
                    self.getrsa_response_js = getrsa_response.json()
#                    print('\ngetrsa resp:\n',self.getrsa_response_js)
                else:
#                    print('\nsomething error,wait and retry getrsa\n')
                    time.sleep(1)
                    self.get_rsa_retry_num -= 1
                    if self.get_rsa_retry_num != 0:
                        self.getrsa()
                    else:
                        print('get rsa key defeat')
                        self.defeat_flag = True
            except:
#                print('\nconnection error,wait and retry\n')
                if self.get_rsa_retry_num != 0:
                    time.sleep(1)
                    self.getrsa()
                else:
                    print('get rsa key defeat')
                    self.defeat_flag = True

    def encrypt_password(self):
        if self.defeat_flag ==False:
            pub_mod = self.getrsa_response_js.get('publickey_mod')
            pub_exp = self.getrsa_response_js.get('publickey_exp')
            self.timestamp = self.getrsa_response_js.get('timestamp')
            key = rsa_publickey(intBase(pub_mod, 16),
                                     intBase(pub_exp, 16),
                                     )         
            self.password_encrypt = b64encode(pkcs1v15_encrypt(key, self.password.encode('ascii')))
#            print('encrypt password success')
        
        
    def get_guard_code(self):
        code = input('令牌(输入后回车):')
        return code

    def dologin(self):
#        print('dologin\n')
        if self.defeat_flag == False:
            self.dologin_retry_num -= 1
            if self.dologin_retry_num == 0:
                self.defeat_flag = True
            self.aligned_time = int(time.time()) + self.time_offset
            
            if self.need_phone_guard_number_flag == True:
                self.phone_guard_number = self.get_guard_code()
                print('guard code: ',self.phone_guard_number)

            self.dologin_post_data={
                    'donotcache':str(int(time.time()*1000)),
                    'username':self.username,
                    'password':self.password_encrypt,
                    'twofactorcode':self.phone_guard_number,
                    'emailauth':'',
                    'loginfriendlyname':'',
                    'captchagid':self.captchagid,
                    'captcha_text':self.captcha_text,
                    'emailsteamid':'',
                    'rsatimestamp':self.timestamp,
                    'remember_login':'true',
                    }
            if self.defeat_flag == False:
                dologin_response = self.req.post(url='https://store.steampowered.com/login/dologin/',
                                            headers=self.header,data=self.dologin_post_data)

                self.dologin_response_html = dologin_response.json()   
#                print('\nddologin_resn resp\n',self.dologin_response_html)
            
                self.detect_login_complete()
        
    def get_captcha(self,captcha_gid):
        print('登陆需要验证码,获取验证码...')
        resp = self.req.get(url = 'https://store.steampowered.com/login/rendercaptcha/?gid='+captcha_gid,
                 headers=self.header,timeout = 15)
        if resp.status_code == 200:
            print('验证码自动识别...')
            time.sleep(1)
            with open('./captcha.png','wb') as fn:
                fn.write(resp.content)
            #self.captcha_text = CaptchaAPI().send_req()    ### 打码API
            self.dologin()  
        else:
            self.dologin()
    
    def detect_login_complete(self):
        if self.defeat_flag == False:
            while(self.dologin_flag):
      
                if (self.dologin_response_html.get('success') == False) and (self.dologin_response_html.get('message') == 'The account name or password that you have entered is incorrect.'):
                    print('账户名或密码错误')
                    self.defeat_flag = True
                    self.dologin_flag = False
                    time.sleep(1)

                elif (self.dologin_response_html.get('success') == False) and (self.dologin_response_html.get('message') == '您输入的帐户名称或密码错误。'):
                    print('账户名或密码错误')
                    self.defeat_flag = True
                    self.dologin_flag = False
                    time.sleep(1)

                elif (self.dologin_response_html.get('success') == False) and (self.dologin_response_html.get('captcha_needed') == True):
                    self.captchagid = self.dologin_response_html.get('captcha_gid')
                    if self.captchagid != None:
#                        print('\ncaptcha_gid:\n',self.captchagid)
                        self.get_captcha(self.captchagid)
                        self.dologin_flag = False
                    
                elif (self.dologin_response_html.get('success') == False) and (self.dologin_response_html.get('message') == ''):
                    self.need_phone_guard_number_flag = True
                    self.dologin()
                    self.dologin_flag = False
                    
                elif (self.dologin_response_html.get('success') == True) and (self.dologin_response_html.get('login_complete') == True):
                    
                    self.dologin_flag = False                                                               
                    self.save_cookie()
                    
                elif (self.dologin_response_html.get('success') == False) and (self.dologin_response_html.get('requires_twofactor') == False) and (self.dologin_response_html.get('captcha_needed') == False):
                    self.too_many_defeats = True
                    self.dologin_flag = False  
                    
                    return None
      
    def save_cookie(self):
        cookie_data = self.req.cookies.get_dict()
        print(cookie_data)
            
        with open('./{}.txt'.format(self.username),'w') as fn:
            fn.write(json.dumps(cookie_data))         



    def entrance(self):
        print('登陆中...')
        self.get_sessionid()
        self.getrsa()
        self.encrypt_password()
        self.dologin()
        
        if self.defeat_flag == False and self.too_many_defeats == False:
            print('登陆成功!')
            time.sleep(2.5)

            return True
        elif self.too_many_defeats == True:
            print('登陆失败次数过多,STEAM限制登陆!')
            time.sleep(2.5)
            return False
        else:
            print('登陆失败!!!,请重试')
            time.sleep(2.5)
            return False


def login():
    print('与STEAM服务器校准时间...')
    time_offset = TimeAligner().get_time_offset()

    print('校准时间成功!')
    time.sleep(0.5)
        
    print('请输入STEAM账号密码(输入后回车)')
    username = input('账号:')
    password = input('密码:')

    AccountWebLogin(username,password,time_offset).entrance()




        
           
def weblogin():
    print('Steam WebLogin')  

    login()
            
if __name__ == '__main__':
    weblogin()

        











