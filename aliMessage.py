from django.conf import settings
import requests
from urllib.parse import quote_plus
import json, random
from hashlib import sha1
import hmac
import datetime, time
import base64

message_url = "https://dysmsapi.aliyuncs.com/"


class AliMessage():
    def __init__(self, AccessKeyId, AccessKeySecret, Action, SignatureMethod="HMAC-SHA1", message_url=message_url):
        # 获取AccessKeyID
        self.AccessKeyId = AccessKeyId
        # 获取AccessKeyId的加密串，并将其拼接为正确的字符串
        self.AccessKeySecret = AccessKeySecret + "&"
        # 请求方式
        self.Action = Action
        # 签名所使用的算法
        self.SignatureMethod = SignatureMethod
        self.message_url = message_url

    def build_body(self):
        # 设置固定的必要参数，不会因为内容而更改
        par_dict = {
            "AccessKeyId": self.AccessKeyId,
            "Action": self.Action,
            "Format": "json",
            "SignatureMethod": self.SignatureMethod,
            "SignatureVersion": "1.0",
            "Version": "2017-05-25"
        }
        # 由当前时间获得UTC时间
        Timestamp = self.get_Utc_time_stap()
        par_dict["Timestamp"] = Timestamp
        SignatureNonce = settings.SECRET_KEY

        # 签名唯一随机数,为了防止请求被阿里给封掉，每次需要设置不一样的随机数
        SignatureNonce += str(random.randrange(1, 10000000))
        par_dict["SignatureNonce"] = SignatureNonce

        return par_dict

    def new_url_encode(self, string):
        # 根据官方文档需要重构UrlEncode编码；重构为如下模式
        # 即在一般的URLEncode后再增加三种字符替换：
        # 加号 （+）替换成 %20、星号 （*）替换成 %2A、 %7E 替换回波浪号 （~）参考代码如下：
        init_string = quote_plus(string=string)
        return init_string.replace("+", "%20").replace("*", "%2A").replace("%7E", "~")

    def send_message_sign(self, PhoneNumbers, SignName, TemplateCode, TemplateParam, **kwargs):
        par_dict = self.build_body()
        # 获取每次发送不同的参数：手机号，发送信息
        send_message_par = {
            "PhoneNumbers": PhoneNumbers,
            "SignName": SignName,
            "TemplateCode": TemplateCode,
        }
        # 由于TemplateParam是字典
        send_message_par["TemplateParam"] = json.dumps(TemplateParam, ensure_ascii=True)
        # 通过send_message_par 进行原先字典更新
        par_dict.update(send_message_par)
        # 一些非必需参数的更新
        par_dict.update(kwargs)
        # 按照ascii 进行代码的更新
        sort_par = self.parameter_sorted(par_dict)

        unsigned_string = "&".join(
            ["%s=%s" % (self.new_url_encode(item[0]), self.new_url_encode(item[1])) for item in sort_par])
        sign_prefix = "GET" + "&" + self.new_url_encode("/")
        # 组合待签名字符串
        unsigned_string = sign_prefix + "&" + self.new_url_encode(unsigned_string)
        # 生成签名
        sign_string = self.sign(unsigned_string.encode("utf-8"))
        request_par = "&".join(["%s=%s" % (key, self.new_url_encode(value)) for key, value in sort_par])
        # 拼接成请求参数
        sign_request_par = request_par + "&Signature=" + self.new_url_encode(sign_string)

        return sign_request_par

    def get_request_url(self, PhoneNumbers, SignName, TemplateCode, TemplateParam, **kwargs):
        # 获取获取短信的路径
        sign_request_par = self.send_message_sign(PhoneNumbers, SignName, TemplateCode, TemplateParam, **kwargs)
        return self.message_url + "?" + sign_request_par

    def parameter_sorted(self, par_dict):
        # 对其待签名的请求参数，去掉"Signature"，进行acsii 进行排序
        par_dict.pop("Signature", None)
        # 生成一个列表，列表元素为单个的元组 ===》 (key,value)
        par_list = [(key, item) for key, item in par_dict.items()]
        sort_par = sorted(par_list)
        return sort_par

    def get_Utc_time_stap(self):
        """由本地时间转换获取UTC标准时间"""

        time_stamp = time.time()
        # 获取本地时间
        # local_time = time.localtime(time_stamp)
        # 获取UTC时间
        utc_time = datetime.datetime.utcfromtimestamp(time_stamp)
        # UTC时间转换为北京时间
        # time2 = utc_time + datetime.timedelta(hours=8)

        return utc_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    def sign(self, unsign_string):

        sign_secret = self.AccessKeySecret.encode("utf-8")
        # 利用 hmac 对其 按照sha1方式进行加密
        signature = hmac.new(sign_secret, unsign_string, sha1).digest()
        # 加密后获得其base64编码的值
        sign = base64.b64encode(signature)
        return sign.decode("utf-8")


def message():
    alipay_par = settings.ALIPAYMESSAGE_PARAMETER
    AccessKeyId = alipay_par.get("AccessKeyId")
    AccessKeySecret = alipay_par.get("AccessKeySecret")
    Action = alipay_par.get("Action")
    return AliMessage(AccessKeySecret=AccessKeySecret,AccessKeyId=AccessKeyId,Action=Action)

def request_send_message(url,**kwargs):

    response = requests.get(url)
    if str(response.status_code) != "200":
        return {"status":"200","message":"请求式表"}
    data = response.json()
    if data.get("Code") != "OK":
        return {"status":"400","message":"代码有误"}
    return {"status":"200","message":data.get('BizId',None)}


if __name__ == '__main__':
    ali = AliMessage(AccessKeyId="LTAIv78dFV8imhry", AccessKeySecret="4bSCXX4jSon6Er35aK6SWoqMi9e0tL",
                     Action="SendSms")

    TemplateCode = "SMS_160572932"
    SignName = "据兰书馆"
    TemplateParam = {"code": "aasdda"}
    sign_string = ali.send_message_sign(PhoneNumbers="13310131625",
                                        TemplateParam=TemplateParam, TemplateCode=TemplateCode, SignName=SignName)
    print(sign_string)
