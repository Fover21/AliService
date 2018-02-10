#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
    阿里主体服务实现(此项目会迭代更新)
        支付模块(支付宝支付相关配置以及PC端支付接口实现)
        转账查询模块(支付宝转账相关配置以及PC端转账接口的实现)
        实名认证模块(支付宝实名认证相关配置以及PC端实名认证接口的实现)
"""

from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

from urllib.parse import quote_plus
from base64 import decodebytes, encodebytes

from config import settings

import json


class AliBase(object):
    """
    接入阿里第三方服务的一些公共方法及属性的使用
    """
    app_id = settings.AliConfig.app_id

    app_private_key_path = settings.AliConfig.merchant_private_key_path

    ali_public_key_path = settings.AliConfig.ali_public_key_path

    debug = settings.AliConfig.debug

    def __init__(self):
        self.app_private_key = None
        self.ali_public_key = None
        self.return_url = None
        self.app_notify_url = None

        # 加载应用的私钥
        with open(self.app_private_key_path) as fp:
            self.app_private_key = RSA.importKey(fp.read())

        # 加载支付宝公钥
        with open(self.ali_public_key_path) as fp:
            self.ali_public_key = RSA.importKey(fp.read())

        if self.debug is True:
            self._gateway = "https://openapi.alipaydev.com/gateway.do"
        else:
            self._gateway = "https://openapi.alipay.com/gateway.do"

    def build_body(self, api, biz_content, return_url=None):
        """构建请求体.

            公有请求体 + 业务请求体

        Parameters
        ----------
        api : string
            请求API

        biz_content: dict
            业务参数

        return_url: string
            实名认证成功回调url

        Returns
        -------
        请求参数: dict
        """
        data = {
            "app_id": self.app_id,
            "method": api,
            "charset": "utf-8",
            "sign_type": "RSA2",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0",
            "biz_content": biz_content
        }

        # 这里的 return_url 用于实名认证成功回调
        if return_url is not None:
            data["return_url"] = return_url

        # 支付接口 同步 + 异步 回调
        if self.return_url is not None:
            data["notify_url"] = self.app_notify_url
            data["return_url"] = self.return_url

        return data

    def generate_url(self, query_string):
        """生成请求url.

            URL = 支付宝网关 + 请求数据

        Parameters
        ----------
        query_string : string
            请求数据

        Returns
        -------
        请求url(get请求)
        """
        return "{url}?{query_string}".format(url=self._gateway, query_string=query_string)

    def sign(self, unsigned_string):
        # 开始计算签名
        key = self.app_private_key
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(SHA256.new(unsigned_string))
        # base64 编码，转换为unicode表示并移除回车
        sign = encodebytes(signature).decode("utf8").replace("\n", "")
        return sign

    def sign_data(self, data):
        data.pop("sign", None)
        # 排序后[(k, v), ...]
        ordered_items = self.ordered_data(data)
        # 拼接成待签名的字符串
        unsigned_string = "&".join("{0}={1}".format(k, v) for k, v in ordered_items)
        # 对上一步得到的字符串进行签名
        sign = self.sign(unsigned_string.encode("utf-8"))
        # 处理URL
        quoted_string = "&".join("{0}={1}".format(k, quote_plus(v)) for k, v in ordered_items)
        # 添加签名，获得最终的订单信息字符串
        signed_string = quoted_string + "&sign=" + quote_plus(sign)
        return signed_string

    def verify(self, data, signature):
        """验证签名

        Parameters
        ----------
        data : dict
            加密数据

        signature : string
            签名值

        Returns
        -------
        bool
        """
        if "sign_type" in data:
            data.pop("sign_type")
        # 排序后的字符串
        ordered_items = self.ordered_data(data)
        message = "&".join(u"{}={}".format(k, v) for k, v in ordered_items)
        return self._verify(message, signature)

    def _verify(self, raw_content, signature):
        """使用支付宝的公钥去加密原始数据，然后和签名值比较

        Parameters
        ----------
        raw_content : string
            原始数据

        signature : string
            签名值

        Returns
        -------
        bool
        """
        key = self.ali_public_key
        signer = PKCS1_v1_5.new(key)
        digest = SHA256.new()
        digest.update(raw_content.encode("utf8"))
        if signer.verify(digest, decodebytes(signature.encode("utf8"))):
            return True
        return False

    @staticmethod
    def ordered_data(data):
        # 排序
        return sorted(
            ((k, v if not isinstance(v, dict) else json.dumps(v, separators=(',', ':'))) for k, v in data.items())
        )


class AliCertification(AliBase):
    """
    阿里实名认证相关接口实现, 实名认证三步走 >

        认证初始化 > 开始认证 > 认证查询

    """

    def __init__(self):
        super(AliCertification, self).__init__()

    def authentication_initialize(self, transaction_id, identity_param, product_code=None, biz_code=None, **kwargs):
        """认证初始化.

        在使用认证接口之前(zhima.customer.certification.certify),
        需要先调用认证初始化接口,获取biz_no,然后在通过biz_no进行认证

        Parameters
        ----------
        transaction_id : string
            商户请求的唯一标志

        identity_param : dict
            {
                "identity_type": "CERT_INFO",
                "cert_type": "IDENTITY_CARD",
                "cert_name": "",  身份证对应姓名
                "cert_no": "" 身份证号码
            }

        product_code : string
            固定值: w1010100000000002978

        biz_code : string
            固定值: FACE

        Returns
        -------
        获取认证初始化接口的请求数据
        """
        if product_code is None:
            product_code = "w1010100000000002978"

        if biz_code is None:
            biz_code = "FACE"

        biz_content = {
            "transaction_id": transaction_id,
            "product_code": product_code,
            "biz_code": biz_code,
            "identity_param": identity_param,
        }
        biz_content.update(kwargs)
        data = self.build_body("zhima.customer.certification.initialize", biz_content)
        return self.sign_data(data)

    def certify(self, biz_no, return_url=None):
        """开始认证.

        在通过认证初始化接口获取的biz_no进行开始认证, 生成认证的URL

        Parameters
        ----------
        biz_no : string
            在请求初始化认证接口获取的biz_no

        return_url : string
            在认证成功之后, 主要向此地址发起get请求, 进行响应的业务处理

        Returns
        -------
        获取开始认证接口的请求数据
        """
        biz_content = {
            "biz_no": biz_no,
        }
        data = self.build_body("zhima.customer.certification.certify", biz_content, return_url)
        return self.sign_data(data)

    def query(self, biz_no):
        """芝麻认证查询.

        在通过认证初始化接口获取的biz_no进行开始认证

        Parameters
        ----------
        biz_no : string
            在请求初始化认证接口获取的biz_no

        Returns
        -------
        获取芝麻认证查询接口的请求数据
        """
        biz_content = {
            "biz_no": biz_no,
        }
        data = self.build_body("zhima.customer.certification.query", biz_content)
        return self.sign_data(data)


class AliTransfer(AliBase):
    """
    支付宝转账及转账查询接口
    """

    def __init__(self):
        super(AliTransfer, self).__init__()

    def transfer_pay(self, out_biz_no, payee_account, amount, **kwargs):
        """转账接口.

        Parameters
        ----------
        out_biz_no : string
            商户转账唯一凭证

        payee_account : string
            收款方账户

        amount : string or int or float
            转账金额(单位: 元, 保留俩位小数, 最小转帐金额 0.1元)

        kwargs : dict
            以下均为可选参数

            payer_show_name : string
                付款方姓名

            payee_real_name : string
                收款方真实姓名

            remark : string
                转账备注（支持200个英文/100个汉字）。当付款方为企业账户，且转账金额达到（大于等于）50000元，remark不能为空。
                收款方可见，会展示在收款用户的收支详情中。

        Returns
        -------
        获取转账接口的请求数据
        """
        biz_content = {
            "out_biz_no": out_biz_no,
            "payee_account": payee_account,
            "payee_type": "ALIPAY_LOGONID",  # 收款方账户类型
            "amount": amount
        }
        biz_content.update(**kwargs)
        data = self.build_body("alipay.fund.trans.toaccount.transfer", biz_content)
        return self.sign_data(data)

    def transfer_query(self, out_biz_no, order_id, **kwargs):
        """转账交易查询接口.

        Parameters
        ----------
        out_biz_no : string
            商户转账唯一凭证

        order_id : string
            支付宝商户转账唯一凭证

        Returns
        -------
        获取转账交易查询接口的请求数据
        """
        biz_content = {
            "out_biz_no": out_biz_no,
            "order_id": order_id
        }
        biz_content.update(kwargs)
        data = self.build_body("alipay.fund.trans.order.query", biz_content)
        return self.sign_data(data)


class AliPay(AliBase):
    """
    支付宝支付接口
    """

    def __init__(self, app_notify_url=None, return_url=None):
        super(AliPay, self).__init__()
        self.app_notify_url = app_notify_url
        self.return_url = return_url

    def direct_pay(self, subject, out_trade_no, total_amount, **kwargs):
        """PC支付接口. 文档DOC地址: https://docs.open.alipay.com/270/alipay.trade.page.pay

        Parameters
        ----------
        subject : string
            订单标题

        out_trade_no : string
            商户订单号唯一凭证

        total_amount : string or float or int
            支付金额，单位元，精确到分

        kwargs : dict
            以下均为可选参数

            body : string
                订单描述

            goods_detail : json
                订单包含的商品列表信息，Json格式： {&quot;show_url&quot;:&quot;https://或http://打头的商品的展示地址&quot;}
                在支付时，可点击商品名称跳转到该地址

            passback_params : string
                公用回传参数，如果请求时传递了该参数，则返回给商户时会回传该参数。
                支付宝只会在异步通知时将该参数原样返回。
                本参数必须进行UrlEncode之后才可以发送给支付宝

            goods_type : int
                商品主类型：0; 虚拟类商品，1; 实物类商品（默认）

            extend_params :
                业务扩张参数(主要用于接入花呗分期)

        Returns
        -------
        获取PC支付接口的请求数据
        """
        biz_content = {
            "subject": subject,
            "out_trade_no": out_trade_no,
            "total_amount": total_amount,
            "product_code": "FAST_INSTANT_TRADE_PAY",  # 销售产品码，目前仅支持这个类型
            # "qr_pay_mode":4
        }

        biz_content.update(**kwargs)
        data = self.build_body("alipay.trade.page.pay", biz_content)
        return self.sign_data(data)


# PC支付API
ali_pay = AliPay(app_notify_url=settings.AliConfig.pay_notify_url, return_url=settings.AliConfig.pay_return_url)

# 实名认证API
ali_certification = AliCertification()

# 转账API
ali_transfer = AliTransfer()
