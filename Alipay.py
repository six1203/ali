import json,os

from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from urllib.parse import quote_plus
from base64 import decodebytes, encodebytes
from django.conf import settings
from ali.keys.acquire_config import ali_pay_parameter


ali_parameter = ali_pay_parameter()


class ali:
    def __init__(self, app_id=ali_parameter["ali_app_id"], pub_key_file=ali_parameter["ali_public_key"],
                 private_key_file=ali_parameter["ali_private_key"], charset="utf-8"):

        self.app_id = app_id
        self.pub_key_file = pub_key_file
        print(os.path.exists(self.pub_key_file))
        self.private_key_file = private_key_file
        print(os.path.exists(self.private_key_file))
        self.charset = charset
        # 获取公钥
        with open(self.pub_key_file) as fp:
            self.app_public_key = RSA.importKey(fp.read())
        # 获取私钥
        with open(self.private_key_file) as fp:
            self.app_private_key = RSA.importKey(fp.read())

        # 判断是否是测试环境
        if settings.DEBUG:
            self.access_url = "https://openapi.alipaydev.com/gateway.do"
        else:
            # 则使用正式环境
            self.access_url = "https://openapi.alipay.com/gateway.do"

    def common_parameter(self):

        # 设置公共参数字典
        common_par = {
            "app_id": self.app_id,
            "format": "json",
            "charset": self.charset,
            "sign_type": "RSA2",
            "version": "1.0",
        }
        # 为其添加时间
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        common_par["timestamp"] = current_time

        return common_par

    def parameter_dict(self, common_par):
        sorted_par = self.sorted_parameter(common_par)
        # 生成待签名字符串
        unsigned_string = "&".join(["%s=%s" % (item, value) for item, value in sorted_par])
        # 利用待签名字符串进行签名
        sign = self.sign(unsigned_string.encode("utf-8"))
        common_par["sign"] = sign
        return json.dumps(common_par, ensure_ascii=False)

    def generate_url(self, common_par):
        print(common_par)
        # 根据参数字典自动生成 url
        sorted_par = self.sorted_parameter(common_par)
        # 生成待签名字符串
        unsigned_string = "&".join(["%s=%s" % (item, value) for item, value in sorted_par])
        # 利用待签名字符串进行签名
        sign = self.sign(unsigned_string.encode("utf-8"))
        # 凭接请求参数
        request_par = "&".join(["{key}={value}".format(key=key, value=quote_plus(value)) for key, value in sorted_par])
        # 将签加至末尾
        request_par += "&sign=" + quote_plus(sign)
        # 返回访问的url
        return self.access_url + "?" + request_par

    def sorted_parameter(self, common_par):
        print(common_par)
        common_par.pop("sign", None)
        common_par_list = []
        for item, value in common_par.items():
            if isinstance(value, dict):
                value = json.dumps(value, ensure_ascii=True)
            common_par_list.append((item, value))

        # 对器序列化后的参数进行排序
        sorted_par = sorted(common_par_list)
        return sorted_par

    def sign(self, unsigned_string):
        # 开始计算签名
        key = self.app_private_key  # 用户私钥 进行签名
        signer = PKCS1_v1_5.new(key)  # 使用SHA256进行签名 # 导入key
        signature = signer.sign(SHA256.new(unsigned_string))
        # base64 编码，转换为unicode表示并移除回车，对字符串进行base64编码
        sign = encodebytes(signature).decode("utf8").replace("\n", "")
        return sign

    def _verify(self, raw_content, signature):
        # 开始计算签名
        key = self.app_public_key
        signer = PKCS1_v1_5.new(key)
        digest = SHA256.new()
        digest.update(raw_content.encode("utf8"))

        if signer.verify(digest, decodebytes(signature.encode("utf8"))):
            return True
        return False

    def verify(self, data, signature):
        if "sign_type" in data:
            sign_type = data.pop("sign_type")
        # 排序后的字符串
        unsigned_items = self.sorted_parameter(data)
        message = "&".join(u"{}={}".format(k, v) for k, v in unsigned_items)
        return self._verify(message, signature)


class AliPay(ali):
    """支付相关操作"""

    def pay_biz_content(self, out_trade_no, total_amount, subject, **kwargs):

        # 构建支付请求参数集合
        biz_content = {
            "out_trade_no": out_trade_no,
            "total_amount": total_amount,
            "subject": subject,
        }
        # 更新可选参数
        biz_content.update(kwargs)

        return biz_content

    def ali_pay(self, method=None, return_url=None, notify_url=None):

        # 支付宝支付处理
        pay_par = {}
        if not method:
            method = "alipay.trade.page.pay"
        pay_par["method"] = method

        if return_url:
            # 同步返回的网址
            pay_par["return_url"] = return_url
            # 异步回调网址
            pay_par["notify_url"] = notify_url

        pay_par["biz_content"] = {}
        # 将其拼接到公共参数中
        common_par = self.common_parameter()
        common_par.update(pay_par)

        return common_par

    def trade_content(self, out_trade_no=None, trade_no=None, **kwargs):

        if not any([out_trade_no, trade_no]):
            raise ValueError("out_trade_no和trade_no两者不能同时为None")
        biz_content = {}
        # 商户订单号
        if out_trade_no:
            biz_content["out_trade_no"] = out_trade_no
        # 支付宝交易号
        if trade_no:
            biz_content["trade_no"] = trade_no

        return biz_content

    def ali_trade_pay_url(self, out_trade_no, total_amount, subject, return_url=None, notify_url=None, **kwargs):

        # 获取公共参数
        common_par = self.ali_pay(return_url, notify_url)
        # 获取阿里请求参数
        biz_content = self.pay_biz_content(out_trade_no, total_amount, subject, **kwargs)
        common_par["biz_content"].update(biz_content)
        # 对参数进行排序，并且同时对字典进行序列化，组成待验签字符串
        # sorted_par = self.sorted_parameter(common_par)
        # # 生成待签名字符串
        # unsigned_string = "&".join(["%s=%s" %(item,value) for item,value in sorted_par])
        # # 利用待签名字符串进行签名
        # sign = self.sign(unsigned_string.encode("utf-8"))
        # # 凭接请求参数
        # request_par = "&".join(["{key}={value}".format(key=key,value=quote_plus(value)) for key,value in sorted_par])
        # # 将签加至末尾
        # request_par += "&sign="+quote_plus(sign)
        # # 返回访问的url
        # return self.access_url +  "?" + request_par
        request_url = self.parameter_dict(common_par)
        return request_url

    def ali_trade_query(self, method="alipay.trade.query", out_trade_no=None, trade_no=None):
        # 获取公共参数
        common_par = self.ali_pay(method=method)
        # 获取阿里请求参数
        biz_content = self.trade_content(out_trade_no, trade_no)
        common_par["biz_content"].update(biz_content)
        request_url = self.parameter_dict(common_par)
        return request_url


class AliLogin(ali):

    def auth_token(self, code=None, refresh_token=None):
        # 获取公共请求参数
        ''''''
        common_par = self.common_parameter()
        # 设置请求方式
        method = "alipay.system.oauth.token"
        common_par["method"] = method
        # 拼接所有的请求参数
        if not any([code, refresh_token]):
            raise ValueError("code和refresh_token不得同时为None")
        if code:
            common_par["grant_type"] = "authorization_code"
            common_par["code"] = code
        else:
            common_par["grant_type"] = "refresh_token"
            common_par["refresh_token"] = refresh_token

        request_url = self.generate_url(common_par)
        return request_url

    def user_info_share(self, auth_token, app_auth_token=None):

        common_par = self.common_parameter()
        # 设置请求方式
        method = "alipay.user.info.share"
        common_par["method"] = method
        if app_auth_token:
            common_par["app_auth_token"] = app_auth_token
        common_par["auth_token"] = auth_token

        # 获取待签名的完整请求路径
        request_url = self.generate_url(common_par)
        return request_url


def AliAppAuth(redirect_url, app_id=ali_parameter["ali_app_id"]):
    """前端跳转进行阿里登录的网址"""
    if not settings.DEBUG:
        access_url = "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?"
    else:
        access_url = "https://openauth.alipaydev.com/oauth2/publicAppAuthorize.htm?"

    par_dict = {
        "app_id": app_id,
        "scope": "auth_user,auth_base",
        "state": ali_parameter["SECRET_KEY"],  # 最好换成本地配置文件可读
    }

    par_dict["redirect_uri"] = quote_plus(redirect_url)

    par_string = "&".join(["%s=%s" % (key, value) for key, value in par_dict.items()])

    return access_url + par_string


def check_app_id_status(app_id, status):
    if (app_id != ali_parameter["ali_app_id"] or
            status != ali_parameter["SECRET_KEY"]):
        return False
    return True


import requests

url = "https://openapi.alipaydev.com/gateway.do"


def request_url(access_url, flag):
    response = requests.get(access_url)
    if str(response.status_code) == "200":
        # print("test",response.content)
        acquire_date = response.json()
        if flag:
            token_info = acquire_date.get("alipay_system_oauth_token_response", None)
        # token_info 应该需要验签
        else:
            token_info = acquire_date.get("alipay_user_info_share_response")
        return token_info
    else:
        return False


ali_pay = AliPay()

__all__ = ["AliAppAuth", "AliLogin", "ali_pay", "check_app_id_status", "request_url" ]