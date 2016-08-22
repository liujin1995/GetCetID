#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os, random, requests, ast,time
from ctypes.util import find_library
from ctypes import CDLL, c_char, c_int, byref, create_string_buffer, Structure, Union


def get_info(name,cet_type):
    USER_AGENT = os.environ.get('USER_AGENT', 'User-Agent: Mozilla/5.0')
    mac = '-'.join(['%.2X' % random.randint(0, 16) for i in xrange(6)])
    param_data = u'type=%d&provice=44&school=广东科技学院&name=%s&examroom=&m=%s' % (cet_type,name, mac)
    param_data = param_data.encode('gbk')
    headers={'User-Agent': USER_AGENT}
    #数据编码处理
    SCHOOL_LAN_PROXIES = {
		"http": "绕过防火墙的代理服务器地址"
	}
    encrypted_data = process_data(param_data, 'PgidW;O;', is_enc=1)
    resp = requests.post(url='http://find.cet.99sushe.com/search', data=encrypted_data, headers=headers, proxies=SCHOOL_LAN_PROXIES, timeout=5)
    #数据解码处理
    ticket_number = process_data(resp.content[2:], '021yO6d<', is_enc= 0)

    print resp.content

    print ticket_number



	
# 数据处理
def process_data(indata, key, is_enc=1):
	DES_LONG = c_int
	DES_cblock = c_char * 8
	libcrypto = CDLL(find_library('crypto'))
	class ks(Union):
		_fields_ = [
		    ('cblock', DES_cblock),
		    ('deslong', DES_LONG * 2)
		]

	class DES_key_schedule(Structure):
		_fields_ = [
		    ('ks', ks * 16),
		]
	length = len(indata)
	indata = create_string_buffer(indata, length)
	outdata = create_string_buffer(length)
	n = c_int(0)
	key = DES_cblock(*tuple(key))
	key_schedule = DES_key_schedule()
	libcrypto.DES_set_odd_parity(key)
	libcrypto.DES_set_key_checked(byref(key), byref(key_schedule))
	libcrypto.DES_cfb64_encrypt(byref(indata), byref(outdata), c_int(length),
	                                 byref(key_schedule), byref(key), byref(n), c_int(is_enc))
	return outdata.raw




#输入姓名，返回准考证号
get_info(u'姓名',1)


